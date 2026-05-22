//! Live encrypted tunnel session (handshake done, async send/recv of plaintext frames).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use fips203_core::{ascii_valid, pack_line, payload_is_quit, MAX_MSG};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use crate::config::TunnelConfig;
use crate::crypto_tunnel::{handshake_client, handshake_server, SessionHandle};
use crate::runtime::{display_plain, recv_loop, tx_loop, PlainMsg, SharedSession, WriteHalf};
use crate::shutdown::watch_signals;

/// How background I/O tasks behave after handshake.
#[derive(Clone, Copy, Debug, Default)]
pub enum LinkMode {
    /// Application drives send/recv; no stdin echo or auto-echo.
    #[default]
    Application,
    /// Decrypt, print MsgPack lines, read stdin and send (client CLI).
    StdinClient,
    /// Decrypt, print, echo plaintext back (server CLI).
    EchoServer,
}

/// Established tunnel: decrypting recv task + encrypting tx task over one TCP connection.
pub struct TunnelLink {
    mode: LinkMode,
    shutdown: Arc<AtomicBool>,
    shared: Arc<SharedSession>,
    wr: WriteHalf,
    incoming: mpsc::Receiver<PlainMsg>,
    outgoing: mpsc::Sender<PlainMsg>,
    recv_task: JoinHandle<()>,
    tx_task: JoinHandle<()>,
    signal_task: JoinHandle<()>,
}

impl TunnelLink {
    /// Connect as client, complete PSK+ML-KEM handshake, start record I/O tasks.
    pub async fn connect(host: &str, port: u16, cfg: &TunnelConfig) -> std::io::Result<Self> {
        Self::connect_mode(host, port, cfg, LinkMode::Application).await
    }

    pub async fn connect_mode(
        host: &str,
        port: u16,
        cfg: &TunnelConfig,
        mode: LinkMode,
    ) -> std::io::Result<Self> {
        let stream = TcpStream::connect((host, port)).await?;
        stream.set_nodelay(true)?;
        let (rd, wr) = stream.into_split();
        Self::from_client_halves(rd, wr, cfg, mode).await
    }

    /// Bind, accept one connection, complete handshake as server.
    pub async fn accept(bind_port: u16, cfg: &TunnelConfig) -> std::io::Result<(Self, std::net::SocketAddr)> {
        Self::accept_mode(bind_port, cfg, LinkMode::Application).await
    }

    pub async fn accept_mode(
        bind_port: u16,
        cfg: &TunnelConfig,
        mode: LinkMode,
    ) -> std::io::Result<(Self, std::net::SocketAddr)> {
        let listener = TcpListener::bind(("0.0.0.0", bind_port)).await?;
        let (stream, addr) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let link = Self::from_server_stream(stream, cfg, mode).await?;
        Ok((link, addr))
    }

    /// Server handshake on an already-accepted stream.
    pub async fn from_server_stream(
        stream: TcpStream,
        cfg: &TunnelConfig,
        mode: LinkMode,
    ) -> std::io::Result<Self> {
        let (rd, wr) = stream.into_split();
        Self::from_server_halves(rd, wr, cfg, mode).await
    }

    async fn from_client_halves(
        mut rd: tokio::net::tcp::OwnedReadHalf,
        wr: tokio::net::tcp::OwnedWriteHalf,
        cfg: &TunnelConfig,
        mode: LinkMode,
    ) -> std::io::Result<Self> {
        let wr = Arc::new(Mutex::new(wr));
        let mut sess = SessionHandle::new(true, cfg.rekey_interval());
        {
            let mut w = wr.lock().await;
            handshake_client(cfg, &mut rd, &mut *w, &mut sess).await?;
        }
        Self::spawn_tasks(rd, wr, sess, cfg, mode).await
    }

    async fn from_server_halves(
        mut rd: tokio::net::tcp::OwnedReadHalf,
        wr: tokio::net::tcp::OwnedWriteHalf,
        cfg: &TunnelConfig,
        mode: LinkMode,
    ) -> std::io::Result<Self> {
        let wr = Arc::new(Mutex::new(wr));
        let mut sess = SessionHandle::new(false, cfg.rekey_interval());
        {
            let mut w = wr.lock().await;
            handshake_server(cfg, &mut rd, &mut *w, &mut sess).await?;
        }
        Self::spawn_tasks(rd, wr, sess, cfg, mode).await
    }

    async fn spawn_tasks(
        rd: tokio::net::tcp::OwnedReadHalf,
        wr: WriteHalf,
        sess: SessionHandle,
        cfg: &TunnelConfig,
        mode: LinkMode,
    ) -> std::io::Result<Self> {
        let stop_tx_on_quit = matches!(mode, LinkMode::StdinClient);
        let display_role = match mode {
            LinkMode::StdinClient => Some("client"),
            LinkMode::EchoServer => Some("server"),
            LinkMode::Application => None,
        };
        let echo = matches!(mode, LinkMode::EchoServer);
        let shutdown = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(SharedSession {
            inner: Mutex::new(sess),
            rekey_done: tokio::sync::Notify::new(),
            rekey_ack_timeout_secs: cfg.rekey_ack_timeout_secs(),
            wire_read_timeout_secs: cfg.wire_read_timeout_secs(),
        });

        let (out_tx, out_rx) = mpsc::channel(cfg.queue_depth());
        let (in_tx, in_rx) = mpsc::channel(cfg.queue_depth());

        let sh_recv = Arc::clone(&shutdown);
        let sh_tx = Arc::clone(&shutdown);
        let sh_sig = Arc::clone(&shutdown);
        let ss_recv = Arc::clone(&shared);
        let ss_tx = Arc::clone(&shared);
        let wr_recv = Arc::clone(&wr);
        let wr_tx = Arc::clone(&wr);
        let wr_sig = Arc::clone(&wr);

        let echo_tx = if echo { Some(out_tx.clone()) } else { None };
        let recv_task = tokio::spawn(async move {
            recv_loop(
                sh_recv,
                ss_recv,
                rd,
                wr_recv,
                display_role,
                echo_tx,
                if echo { None } else { Some(in_tx) },
            )
            .await;
        });

        let tx_task = tokio::spawn(async move {
            tx_loop(sh_tx, ss_tx, wr_tx, out_rx, stop_tx_on_quit).await;
        });

        let signal_task = tokio::spawn(async move {
            watch_signals(sh_sig, wr_sig).await;
        });

        let link = Self {
            mode,
            shutdown,
            shared,
            wr,
            incoming: in_rx,
            outgoing: out_tx,
            recv_task,
            tx_task,
            signal_task,
        };

        if matches!(mode, LinkMode::StdinClient) {
            link.spawn_stdin_reader();
        }

        Ok(link)
    }

    fn spawn_stdin_reader(&self) {
        let out = self.outgoing.clone();
        let shutdown = Arc::clone(&self.shutdown);
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let mut lines = BufReader::new(tokio::io::stdin()).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                if !ascii_valid(line.as_bytes()) {
                    eprintln!("client: line is not 7-bit ASCII (ignored)");
                    continue;
                }
                let mut mp = vec![0u8; MAX_MSG + 64];
                match pack_line(line.as_bytes(), &mut mp) {
                    Ok(n) => {
                        mp.truncate(n);
                        if out.send(mp).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => eprintln!("client: MessagePack pack failed (ignored)"),
                }
            }
            shutdown.store(true, Ordering::SeqCst);
        });
    }

    /// Run until the session ends (CLI modes). Application mode should use `recv_payload` / `join` directly.
    pub async fn run_until_close(mut self) -> std::io::Result<()> {
        match self.mode {
            LinkMode::StdinClient => {
                while !self.shutdown.load(Ordering::SeqCst) {
                    match self.recv_payload().await? {
                        Some(p) => display_plain("client", &p),
                        None => break,
                    }
                }
            }
            LinkMode::EchoServer => {
                let mut recv_done = false;
                let mut tx_done = false;
                tokio::select! {
                    r = &mut self.recv_task => {
                        self.shutdown.store(true, Ordering::SeqCst);
                        let _ = r;
                        recv_done = true;
                    }
                    r = &mut self.tx_task => {
                        self.shutdown.store(true, Ordering::SeqCst);
                        let _ = r;
                        tx_done = true;
                    }
                }
                self.shutdown.store(true, Ordering::SeqCst);
                if !tx_done {
                    let _ = self.tx_task.await;
                }
                if !recv_done {
                    let _ = self.recv_task.await;
                }
                let _ = self.signal_task.await;
                return Ok(());
            }
            LinkMode::Application => {}
        }
        self.join().await;
        Ok(())
    }

    pub fn mode(&self) -> LinkMode {
        self.mode
    }

    /// Queue one plaintext frame (already MsgPack-wrapped or control payload).
    pub async fn send_payload(&self, payload: PlainMsg) -> std::io::Result<()> {
        self.outgoing
            .send(payload)
            .await
            .map_err(|_| std::io::Error::other("tunnel tx closed"))
    }

    /// Pack an ASCII line as MsgPack string and send.
    pub async fn send_line(&self, line: &str) -> std::io::Result<()> {
        if !ascii_valid(line.as_bytes()) {
            return Err(std::io::Error::other("line is not 7-bit ASCII"));
        }
        let mut mp = vec![0u8; MAX_MSG + 64];
        let n = pack_line(line.as_bytes(), &mut mp).map_err(|_| std::io::Error::other("pack"))?;
        mp.truncate(n);
        self.send_payload(mp).await
    }

    /// Send the wire-format quit payload (`quit` as MsgPack string).
    pub async fn send_quit(&self) -> std::io::Result<()> {
        self.send_line("quit").await
    }

    /// Wait for the next decrypted plaintext frame.
    pub async fn recv_payload(&mut self) -> std::io::Result<Option<PlainMsg>> {
        match self.incoming.recv().await {
            Some(p) => Ok(Some(p)),
            None => Ok(None),
        }
    }

    pub fn is_quit(payload: &[u8]) -> bool {
        payload_is_quit(payload)
    }

    /// Cooperative shutdown (SIGINT/SIGTERM also trigger this via the signal task).
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Wait until recv/tx/signal tasks finish.
    pub async fn join(self) {
        let Self {
            shutdown,
            wr,
            mut incoming,
            outgoing: _,
            recv_task,
            tx_task,
            signal_task,
            ..
        } = self;
        shutdown.store(true, Ordering::SeqCst);
        signal_task.abort();
        recv_task.abort();
        tx_task.abort();
        let _ = wr.lock().await.shutdown();
        drop(incoming);
        let _ = recv_task.await;
        let _ = tx_task.await;
        let _ = signal_task.await;
    }
}

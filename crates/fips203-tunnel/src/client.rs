//! Client mode: stdin → MsgPack → encrypt; decrypt → display.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use fips203_core::{ascii_valid, pack_line, MAX_MSG};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};

use crate::config::TunnelEnv;
use crate::crypto_tunnel::{handshake_client, SessionHandle};
use crate::runtime::{
    display_plain, recv_loop, tx_loop, PlainMsg, SharedSession, WriteHalf,
};

pub async fn run_client(host: &str, port: u16, env: TunnelEnv) -> std::io::Result<()> {
    let stream = TcpStream::connect((host, port)).await?;
    stream.set_nodelay(true)?;
    let (mut rd, wr) = stream.into_split();
    let wr: WriteHalf = Arc::new(Mutex::new(wr));

    let mut sess = SessionHandle::new(true, env.rekey_interval);
    {
        let mut w = wr.lock().await;
        handshake_client(&env, &mut rd, &mut *w, &mut sess).await?;
    }

    if env.queue_clamped {
        eprintln!(
            "client: queue depth clamped to {} (~{} KiB per plaintext queue)",
            env.queue_depth,
            (env.queue_depth * (std::mem::size_of::<u32>() + MAX_MSG) + 1023) / 1024
        );
    }
    println!(
        "client: handshake complete (queues depth={}, ~{} KiB per plaintext queue)",
        env.queue_depth,
        (env.queue_depth * (std::mem::size_of::<u32>() + MAX_MSG) + 1023) / 1024
    );
    eprintln!("client: plaintext = ASCII lines → MessagePack string → encrypt (stdin)");

    let shutdown = Arc::new(AtomicBool::new(false));
    let shared = Arc::new(SharedSession {
        inner: Mutex::new(sess),
        rekey_done: tokio::sync::Notify::new(),
    });

    let (tx_tx, tx_rx) = mpsc::channel::<PlainMsg>(env.queue_depth);
    let (rx_tx, mut rx_rx) = mpsc::channel::<PlainMsg>(env.queue_depth);

    let sh1 = Arc::clone(&shutdown);
    let sh2 = Arc::clone(&shutdown);
    let sh3 = Arc::clone(&shutdown);
    let ss1 = Arc::clone(&shared);
    let ss2 = Arc::clone(&shared);
    let wr1 = Arc::clone(&wr);
    let wr2 = Arc::clone(&wr);

    let recv_task = tokio::spawn(async move {
        recv_loop(sh1, ss1, rd, wr1, None, None, Some(rx_tx)).await;
    });

    let tx_task = tokio::spawn(async move {
        tx_loop(sh2, ss2, wr2, tx_rx, true).await;
    });

    let stdin_task = tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if sh3.load(Ordering::SeqCst) {
                break;
            }
            let bytes = line.as_bytes();
            if !ascii_valid(bytes) {
                eprintln!("client: line is not 7-bit ASCII (ignored)");
                continue;
            }
            let mut mp = vec![0u8; MAX_MSG + 64];
            match pack_line(bytes, &mut mp) {
                Ok(n) => {
                    mp.truncate(n);
                    if tx_tx.send(mp).await.is_err() {
                        break;
                    }
                }
                Err(_) => eprintln!("client: MessagePack pack failed (ignored)"),
            }
        }
        sh3.store(true, Ordering::SeqCst);
    });

    while !shutdown.load(Ordering::SeqCst) {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                shutdown.store(true, Ordering::SeqCst);
                break;
            }
            msg = rx_rx.recv() => {
                match msg {
                    Some(p) => display_plain("client", &p),
                    None => break,
                }
            }
        }
    }

    shutdown.store(true, Ordering::SeqCst);
    let _ = stdin_task.await;
    let _ = tx_task.await;
    let _ = recv_task.await;
    Ok(())
}

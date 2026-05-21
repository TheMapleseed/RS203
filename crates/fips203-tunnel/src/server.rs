//! Server mode: decrypt → display → echo plaintext back on same TCP stream.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use fips203_core::MAX_MSG;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};

use crate::config::TunnelEnv;
use crate::crypto_tunnel::{handshake_server, SessionHandle};
use crate::runtime::{recv_loop, tx_loop, SharedSession, WriteHalf};

pub async fn run_server(port: u16, env: TunnelEnv) -> std::io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    println!("server: listening on port {port}");
    let (stream, _) = listener.accept().await?;
    stream.set_nodelay(true)?;
    let (mut rd, wr) = stream.into_split();
    let wr: WriteHalf = Arc::new(Mutex::new(wr));

    let mut sess = SessionHandle::new(false, env.rekey_interval);
    {
        let mut w = wr.lock().await;
        handshake_server(&env, &mut rd, &mut *w, &mut sess).await?;
    }

    if env.queue_clamped {
        eprintln!(
            "server: queue depth clamped to {} (~{} bytes for plaintext queue)",
            env.queue_depth,
            env.queue_depth * (std::mem::size_of::<u32>() + MAX_MSG)
        );
    }
    println!(
        "server: handshake complete (queue depth={}, ~{} KiB plaintext buffer)",
        env.queue_depth,
        (env.queue_depth * (std::mem::size_of::<u32>() + MAX_MSG) + 1023) / 1024
    );
    eprintln!("server: decrypt → MessagePack decode → display (ASCII source lines on client)");

    let shutdown = Arc::new(AtomicBool::new(false));
    let shared = Arc::new(SharedSession {
        inner: Mutex::new(sess),
        rekey_done: tokio::sync::Notify::new(),
    });

    let (tx_tx, tx_rx) = mpsc::channel(env.queue_depth);

    let sh1 = Arc::clone(&shutdown);
    let sh2 = Arc::clone(&shutdown);
    let ss1 = Arc::clone(&shared);
    let ss2 = Arc::clone(&shared);
    let wr1 = Arc::clone(&wr);
    let wr2 = Arc::clone(&wr);

    let recv_task = tokio::spawn(async move {
        recv_loop(sh1, ss1, rd, wr1, Some("server"), Some(tx_tx), None).await;
    });

    let tx_task = tokio::spawn(async move {
        tx_loop(sh2, ss2, wr2, tx_rx, false).await;
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            shutdown.store(true, Ordering::SeqCst);
        }
        _ = recv_task => {}
        _ = tx_task => {}
    }

    shutdown.store(true, Ordering::SeqCst);
    Ok(())
}

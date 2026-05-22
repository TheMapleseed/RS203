//! Cooperative shutdown (SIGINT/SIGTERM + TCP half-close), mirroring C `sigwait` + `shutdown(2)`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::io::AsyncWriteExt;

use crate::runtime::WriteHalf;

/// Block until a termination signal; then set `shutdown` and close the write half so `recv` wakes.
pub async fn watch_signals(shutdown: Arc<AtomicBool>, wr: WriteHalf) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => return watch_ctrl_c_only(shutdown, wr).await,
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }

    shutdown.store(true, Ordering::SeqCst);
    let _ = wr.lock().await.shutdown();
}

async fn watch_ctrl_c_only(shutdown: Arc<AtomicBool>, wr: WriteHalf) {
    let _ = tokio::signal::ctrl_c().await;
    shutdown.store(true, Ordering::SeqCst);
    let _ = wr.lock().await.shutdown();
}

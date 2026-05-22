//! TCP handshake smoke (no record I/O tasks).

use std::sync::Arc;
use std::time::Duration;

use fips203_tunnel::{crypto_tunnel::SessionHandle, handshake_client, handshake_server, TunnelConfig};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::time::timeout;

fn test_config() -> TunnelConfig {
    let mut cfg = TunnelConfig::new([0xCD; 32], peer_id(b"c"), peer_id(b"s"));
    cfg.rekey_interval = 10_000_000;
    cfg
}

fn peer_id(label: &[u8]) -> [u8; fips203_tunnel::ID_SIZE] {
    let mut out = [0u8; fips203_tunnel::ID_SIZE];
    out[..label.len()].copy_from_slice(label);
    out
}

#[tokio::test]
async fn tcp_handshake_completes() {
    timeout(Duration::from_secs(5), async {
        let cfg = test_config();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let cfg_srv = cfg.clone();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut rd, wr) = stream.into_split();
            let wr = Arc::new(Mutex::new(wr));
            let mut sess = SessionHandle::new(false, cfg_srv.rekey_interval);
            let mut w = wr.lock().await;
            handshake_server(&cfg_srv, &mut rd, &mut *w, &mut sess).await.unwrap();
            sess.session.epoch
        });

        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (mut rd, wr) = stream.into_split();
        let wr = Arc::new(Mutex::new(wr));
        let mut sess = SessionHandle::new(true, cfg.rekey_interval);
        let mut w = wr.lock().await;
        handshake_client(&cfg, &mut rd, &mut *w, &mut sess).await.unwrap();
        assert_eq!(sess.session.epoch, 0);
        assert_eq!(server.await.unwrap(), 0);
    })
    .await
    .expect("handshake timed out");
}

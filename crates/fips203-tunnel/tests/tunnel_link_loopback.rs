//! Tokio TCP loopback: `TunnelLink` with opaque payloads and MessagePack lines.

use std::time::Duration;

use fips203_core::{decode_string_only, MAX_MSG};
use fips203_tunnel::{LinkMode, TunnelConfig, TunnelLink};
use tokio::net::TcpListener;
use tokio::time::timeout;

fn test_config() -> TunnelConfig {
    let mut cfg = TunnelConfig::new(
        [0xCD; 32],
        padded_id(b"link_client"),
        padded_id(b"link_server"),
    );
    cfg.rekey_interval = 10_000_000;
    cfg
}

fn padded_id(label: &[u8]) -> [u8; fips203_tunnel::ID_SIZE] {
    assert!(label.len() <= fips203_tunnel::ID_SIZE);
    let mut out = [0u8; fips203_tunnel::ID_SIZE];
    out[..label.len()].copy_from_slice(label);
    out
}

async fn run_with_timeout<F, T>(secs: u64, f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    timeout(Duration::from_secs(secs), f)
        .await
        .expect("test timed out")
}

#[tokio::test]
async fn link_opaque_roundtrip() {
    run_with_timeout(10, async {
        let cfg = test_config();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let cfg_srv = cfg.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut link = TunnelLink::from_server_stream(stream, &cfg_srv, LinkMode::Application)
                .await
                .unwrap();
            let payload = link.recv_payload().await.unwrap().expect("one frame");
            assert_eq!(payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
            link.send_payload(payload).await.unwrap();
            link.shutdown();
            drop(link);
        });

        let mut client = TunnelLink::connect("127.0.0.1", port, &cfg).await.unwrap();
        client
            .send_payload(vec![0xDE, 0xAD, 0xBE, 0xEF])
            .await
            .unwrap();
        let back = client.recv_payload().await.unwrap().expect("echo");
        assert_eq!(back, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        client.shutdown();
        drop(client);
        server.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn link_msgpack_line_roundtrip() {
    run_with_timeout(10, async {
        let cfg = test_config();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let cfg_srv = cfg.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut link = TunnelLink::from_server_stream(stream, &cfg_srv, LinkMode::Application)
                .await
                .unwrap();
            let payload = link.recv_payload().await.unwrap().expect("line");
            let mut ascii = [0u8; MAX_MSG];
            let n = decode_string_only(&payload, &mut ascii).expect("msgpack");
            assert_eq!(&ascii[..n], b"ping");
            link.send_line("pong").await.unwrap();
            link.shutdown();
            drop(link);
        });

        let mut client = TunnelLink::connect("127.0.0.1", port, &cfg).await.unwrap();
        client.send_line("ping").await.unwrap();
        let payload = client.recv_payload().await.unwrap().expect("reply");
        let mut ascii = [0u8; MAX_MSG];
        let n = decode_string_only(&payload, &mut ascii).unwrap();
        assert_eq!(&ascii[..n], b"pong");
        client.shutdown();
        drop(client);
        server.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn link_msgpack_then_opaque_same_session() {
    run_with_timeout(10, async {
        let cfg = test_config();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let cfg_srv = cfg.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut link = TunnelLink::from_server_stream(stream, &cfg_srv, LinkMode::Application)
                .await
                .unwrap();
            let first = link.recv_payload().await.unwrap().expect("msgpack");
            let mut ascii = [0u8; MAX_MSG];
            assert!(decode_string_only(&first, &mut ascii).is_ok());
            let second = link.recv_payload().await.unwrap().expect("opaque");
            assert_eq!(second, vec![0x01, 0x02, 0x03]);
            assert!(decode_string_only(&second, &mut ascii).is_err());
            link.shutdown();
            drop(link);
        });

        let mut client = TunnelLink::connect("127.0.0.1", port, &cfg).await.unwrap();
        client.send_line("one").await.unwrap();
        client.send_payload(vec![0x01, 0x02, 0x03]).await.unwrap();
        client.shutdown();
        drop(client);
        server.await.unwrap();
    })
    .await;
}

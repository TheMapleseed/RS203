//! Full PSK + ML-KEM handshake over a socket pair, then opaque + MessagePack frames.

mod support;

use std::mem;
use std::os::unix::net::UnixStream;
use std::thread;

use fips203_core::{
    decode_string_only, handshake_client, handshake_server, pack_line, TunnelRuntime,
};
use support::{client_to_server_plain, server_to_client_plain, test_handshake_config};

#[test]
fn handshake_socket_pair_then_opaque_and_msgpack() {
    let cfg = test_handshake_config();
    let (mut server_io, mut client_io) = UnixStream::pair().expect("unix pair");

    let cfg_srv = test_handshake_config();
    let server = thread::spawn(move || {
        let mut rt = TunnelRuntime::new(false, 1_000_000);
        handshake_server(&mut server_io, &cfg_srv, &mut rt).expect("server hs");
        rt
    });

    let mut client_rt = TunnelRuntime::new(true, 1_000_000);
    handshake_client(&mut client_io, &cfg, &mut client_rt).expect("client hs");
    let mut server_rt = server.join().expect("server thread");

    let mut client = mem::take(&mut client_rt.session);
    let mut server = mem::take(&mut server_rt.session);

    let opaque = [0x10, 0x20, 0x30, 0x40, 0x50];
    assert_eq!(
        client_to_server_plain(&mut client, &mut server, &opaque),
        opaque.as_slice()
    );

    let mut mp = [0u8; 64];
    let n = pack_line(b"post-handshake", &mut mp).unwrap();
    let echoed = server_to_client_plain(&mut server, &mut client, &mp[..n]);
    assert_eq!(&echoed, &mp[..n]);
    let mut show = [0u8; 256];
    let slen = decode_string_only(&echoed, &mut show).unwrap();
    assert_eq!(&show[..slen], b"post-handshake");
}

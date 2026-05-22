//! Minimal `std::net` echo demo (library only — no Tokio).
//!
//! ```bash
//! export TUNNEL_PSK_HEX=<64 hex chars>
//! export TUNNEL_CLIENT_ID=alice
//! export TUNNEL_SERVER_ID=bob
//! cargo run -p fips203-core --example loopback_std -- server 9999
//! cargo run -p fips203-core --example loopback_std -- client 127.0.0.1 9999 hello
//! ```

use std::net::{TcpListener, TcpStream};
use std::process;
use std::thread;
use std::time::Duration;

use fips203_core::{
    decode_string_only, handshake_client, handshake_server, load_handshake_config_from_env,
    load_rekey_interval_from_env, open_plain, pack_line, payload_is_quit, read_wire_frame,
    seal_plain, wire_buffer, write_wire_frame, Error, HandshakeConfig, TunnelRuntime,
    MAX_MSG,
};

fn io_err(_: Error) -> std::io::Error {
    std::io::Error::other("crypto")
}

fn usage(prog: &str) -> ! {
    eprintln!(
        "usage:\n  \
         {prog} server <port>\n  \
         {prog} client <host> <port> <ascii-line>"
    );
    process::exit(1);
}

fn run_server(port: u16, cfg: HandshakeConfig, rekey_interval: u64) -> std::io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    eprintln!("listening on {port}");
    let (mut stream, _) = listener.accept()?;
    stream.set_nodelay(true)?;
    let mut runtime = TunnelRuntime::new(false, rekey_interval);
    handshake_server(&mut stream, &cfg, &mut runtime)?;
    eprintln!("handshake ok");

    let mut wire = wire_buffer();
    let mut plain = vec![0u8; MAX_MSG];
    loop {
        let wl = read_wire_frame(&mut stream, &mut wire)?;
        let plen = open_plain(&mut runtime.session, &wire[..wl], &mut plain).map_err(io_err)?;
        let payload = &plain[..plen];
        let mut show = vec![0u8; MAX_MSG * 4];
        if let Ok(n) = decode_string_only(payload, &mut show) {
            eprintln!("server rx: {}", String::from_utf8_lossy(&show[..n]));
        }
        if payload_is_quit(payload) {
            break;
        }
        let wl = seal_plain(&mut runtime.session, payload, &mut wire).map_err(io_err)?;
        write_wire_frame(&mut stream, &wire, wl)?;
    }
    Ok(())
}

fn run_client(
    host: &str,
    port: u16,
    line: &str,
    cfg: HandshakeConfig,
    rekey_interval: u64,
) -> std::io::Result<()> {
    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect(&addr)?;
    stream.set_nodelay(true)?;
    let mut runtime = TunnelRuntime::new(true, rekey_interval);
    handshake_client(&mut stream, &cfg, &mut runtime)?;
    eprintln!("handshake ok");

    let mut mp = vec![0u8; MAX_MSG + 64];
    let n = pack_line(line.as_bytes(), &mut mp).map_err(io_err)?;
    mp.truncate(n);
    let mut wire = wire_buffer();
    let wl = seal_plain(&mut runtime.session, &mp, &mut wire).map_err(io_err)?;
    write_wire_frame(&mut stream, &wire, wl)?;

    thread::sleep(Duration::from_millis(200));

    let wl = read_wire_frame(&mut stream, &mut wire)?;
    let mut plain = vec![0u8; MAX_MSG];
    let plen = open_plain(&mut runtime.session, &wire[..wl], &mut plain).map_err(io_err)?;
    let mut show = vec![0u8; MAX_MSG * 4];
    if let Ok(slen) = decode_string_only(&plain[..plen], &mut show) {
        println!("client rx: {}", String::from_utf8_lossy(&show[..slen]));
    }

    let mut quit = vec![0u8; 64];
    let qn = pack_line(b"quit", &mut quit).map_err(io_err)?;
    quit.truncate(qn);
    let wl = seal_plain(&mut runtime.session, &quit, &mut wire).map_err(io_err)?;
    write_wire_frame(&mut stream, &wire, wl)?;
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        usage(&args[0]);
    }
    let cfg = match load_handshake_config_from_env() {
        Ok(c) => c,
        Err(_) => {
            eprintln!("set TUNNEL_PSK_HEX, TUNNEL_CLIENT_ID, TUNNEL_SERVER_ID");
            process::exit(1);
        }
    };
    let rekey = load_rekey_interval_from_env();

    let code = match args[1].as_str() {
        "server" if args.len() >= 3 => {
            let port: u16 = args[2].parse().unwrap_or_else(|_| usage(&args[0]));
            match run_server(port, cfg, rekey) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("server: {e}");
                    1
                }
            }
        }
        "client" if args.len() >= 5 => {
            let port: u16 = args[3].parse().unwrap_or_else(|_| usage(&args[0]));
            match run_client(&args[2], port, &args[4], cfg, rekey) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("client: {e}");
                    1
                }
            }
        }
        _ => usage(&args[0]),
    };
    process::exit(code);
}

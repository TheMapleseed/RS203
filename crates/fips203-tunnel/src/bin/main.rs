//! `fips203_tunnel` — stdin client / echo server over encrypted TCP.

use std::env;
use std::process;

use fips203_tunnel::{from_env, parse_port, run_client, run_server};

fn usage(prog: &str) -> ! {
    eprintln!(
        "usage:\n  \
         export TUNNEL_PSK_HEX=<64 hex chars>\n  \
         export TUNNEL_CLIENT_ID=<peer label>\n  \
         export TUNNEL_SERVER_ID=<peer label>\n  \
         # optional: TUNNEL_QUEUE_DEPTH TUNNEL_MAX_QUEUE_MB TUNNEL_MAX_QUEUE_BYTES TUNNEL_REKEY_INTERVAL\n  \
         {prog} server <port>\n  \
         {prog} client <ip> <port>"
    );
    process::exit(1);
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        usage(&args[0]);
    }

    let cfg = match from_env() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    };

    let code = match args[1].as_str() {
        "server" if args.len() >= 3 => match parse_port(&args[2]) {
            Ok(port) => match run_server(port, cfg).await {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("server: {e}");
                    1
                }
            },
            Err(e) => {
                eprintln!("invalid port: {e}");
                1
            }
        },
        "client" if args.len() >= 4 => match parse_port(&args[3]) {
            Ok(port) => match run_client(&args[2], port, cfg).await {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("client: {e}");
                    1
                }
            },
            Err(e) => {
                eprintln!("invalid port: {e}");
                1
            }
        },
        _ => usage(&args[0]),
    };
    process::exit(code);
}

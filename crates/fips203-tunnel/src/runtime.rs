//! Shared recv/tx/control logic.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use fips203_core::{payload_is_quit, MAX_MSG};
use tokio::sync::{mpsc, Mutex, Notify};

use crate::config::REKEY_NONCE_SIZE;
use crate::crypto_tunnel::{
    build_control, is_control, open_frame, random_bytes, rekey_apply, seal_frame, wire_buf,
    SessionHandle, CTRL_ACK, CTRL_LEN, CTRL_REQ,
};
use crate::wire::{read_wire_frame, write_wire_frame};

pub type PlainMsg = Vec<u8>;
pub type WriteHalf = Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>;

pub struct SharedSession {
    pub inner: Mutex<SessionHandle>,
    pub rekey_done: Notify,
}

pub async fn send_plain(sess: &SharedSession, wr: &WriteHalf, plain: &[u8]) -> std::io::Result<()> {
    let mut guard = sess.inner.lock().await;
    let mut wire = wire_buf();
    let wl = seal_frame(&mut guard.crypto, plain, &mut wire)?;
    drop(guard);
    let mut w = wr.lock().await;
    write_wire_frame(&mut *w, &wire, wl).await
}

pub async fn maybe_handle_control(
    sess: &SharedSession,
    wr: &WriteHalf,
    msg: &[u8],
) -> std::io::Result<i32> {
    let mut ty = 0u8;
    let mut want_epoch = 0u32;
    let mut peer_nonce = [0u8; REKEY_NONCE_SIZE];
    if !is_control(msg, &mut ty, &mut want_epoch, &mut peer_nonce) {
        return Ok(0);
    }
    if ty == CTRL_ACK {
        return Ok(0);
    }
    if ty != CTRL_REQ {
        return Err(std::io::Error::other("bad control"));
    }
    let guard = sess.inner.lock().await;
    if want_epoch != guard.crypto.epoch + 1 {
        return Err(std::io::Error::other("epoch"));
    }
    let mut my_nonce = [0u8; REKEY_NONCE_SIZE];
    random_bytes(&mut my_nonce)?;
    let mut ack = [0u8; CTRL_LEN];
    build_control(&mut ack, CTRL_ACK, want_epoch, &my_nonce);
    let is_client = guard.crypto.is_client != 0;
    drop(guard);
    send_plain(sess, wr, &ack).await?;
    let mut guard = sess.inner.lock().await;
    if is_client {
        rekey_apply(&mut guard.crypto, want_epoch, &my_nonce, &peer_nonce);
    } else {
        rekey_apply(&mut guard.crypto, want_epoch, &peer_nonce, &my_nonce);
    }
    Ok(1)
}

pub async fn maybe_initiate_rekey(sess: &SharedSession, wr: &WriteHalf) -> std::io::Result<()> {
    {
        let mut guard = sess.inner.lock().await;
        if guard.crypto.is_client == 0 || guard.crypto.txs < guard.crypto.rekey_interval {
            return Ok(());
        }
        let next_epoch = guard.crypto.epoch + 1;
        let mut my_nonce = [0u8; REKEY_NONCE_SIZE];
        random_bytes(&mut my_nonce)?;
        let mut req = [0u8; CTRL_LEN];
        build_control(&mut req, CTRL_REQ, next_epoch, &my_nonce);
        guard.rekey_my_nonce = my_nonce;
        guard.rekey_pending_epoch = next_epoch;
        guard.rekey_waiting = true;
        let mut wire = wire_buf();
        let wl = seal_frame(&mut guard.crypto, &req, &mut wire)?;
        drop(guard);
        let mut w = wr.lock().await;
        write_wire_frame(&mut *w, &wire, wl).await?;
    }
    loop {
        let waiting = sess.inner.lock().await.rekey_waiting;
        if !waiting {
            break;
        }
        sess.rekey_done.notified().await;
    }
    Ok(())
}

pub async fn recv_loop(
    shutdown: Arc<AtomicBool>,
    sess: Arc<SharedSession>,
    mut rd: tokio::net::tcp::OwnedReadHalf,
    wr: WriteHalf,
    display_role: Option<&'static str>,
    tx_echo: Option<mpsc::Sender<PlainMsg>>,
    mut rx_out: Option<mpsc::Sender<PlainMsg>>,
) {
    let mut wire = wire_buf();
    let mut plain = vec![0u8; MAX_MSG];
    while !shutdown.load(Ordering::SeqCst) {
        let wl = match read_wire_frame(&mut rd, &mut wire).await {
            Ok(n) => n,
            Err(_) => break,
        };
        let plen = {
            let mut guard = sess.inner.lock().await;
            match open_frame(&mut guard.crypto, &wire[..wl], &mut plain) {
                Ok(n) => n,
                Err(_) => break,
            }
        };
        let payload = plain[..plen].to_vec();

        {
            let mut guard = sess.inner.lock().await;
            if guard.crypto.is_client != 0 && guard.rekey_waiting {
                let mut ty = 0u8;
                let mut epoch = 0u32;
                let mut nonce = [0u8; REKEY_NONCE_SIZE];
                if is_control(&payload, &mut ty, &mut epoch, &mut nonce)
                    && ty == CTRL_ACK
                    && epoch == guard.rekey_pending_epoch
                {
                    let my_nonce = guard.rekey_my_nonce;
                    rekey_apply(&mut guard.crypto, epoch, &my_nonce, &nonce);
                    guard.rekey_waiting = false;
                    sess.rekey_done.notify_waiters();
                    continue;
                }
            }
        }

        match maybe_handle_control(&sess, &wr, &payload).await {
            Ok(1) => continue,
            Ok(0) => {}
            Ok(_) => continue,
            Err(_) => break,
        }

        let mut ty = 0u8;
        let mut epoch = 0u32;
        let mut nonce = [0u8; REKEY_NONCE_SIZE];
        if is_control(&payload, &mut ty, &mut epoch, &mut nonce) {
            continue;
        }

        if let Some(role) = display_role {
            display_plain(role, &payload);
        }

        if let Some(tx) = &tx_echo {
            if tx.send(payload.clone()).await.is_err() {
                break;
            }
        }

        if let Some(rx) = &mut rx_out {
            if rx.send(payload.clone()).await.is_err() {
                break;
            }
        }

        if payload_is_quit(&payload) {
            break;
        }
    }
    shutdown.store(true, Ordering::SeqCst);
}

pub async fn tx_loop(
    shutdown: Arc<AtomicBool>,
    sess: Arc<SharedSession>,
    wr: WriteHalf,
    mut rx: mpsc::Receiver<PlainMsg>,
    stop_on_quit: bool,
) {
    while !shutdown.load(Ordering::SeqCst) {
        let msg = match rx.recv().await {
            Some(m) => m,
            None => break,
        };
        if maybe_initiate_rekey(&sess, &wr).await.is_err() {
            break;
        }
        if send_plain(&sess, &wr, &msg).await.is_err() {
            break;
        }
        if stop_on_quit && payload_is_quit(&msg) {
            break;
        }
    }
    shutdown.store(true, Ordering::SeqCst);
}

pub fn display_plain(role: &str, plain: &[u8]) {
    let mut dline = vec![0u8; MAX_MSG * 4];
    if let Ok(n) = fips203_core::decode_string_only(plain, &mut dline) {
        println!("{role} rx: {}", String::from_utf8_lossy(&dline[..n]));
    } else if let Ok(n) = fips203_core::format_decoded(plain, &mut dline) {
        println!("{role} rx: {}", String::from_utf8_lossy(&dline[..n]));
    } else {
        println!("{role} rx: (MessagePack decode error)");
    }
}

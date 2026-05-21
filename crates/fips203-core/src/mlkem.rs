//! ML-KEM-768 — pure Rust port of PQClean `ml-kem-768/clean`.

mod pqclean768;

use crate::error::{Error, Result};
use crate::fips202::shake256;

pub const MLKEM768_EK_SIZE: usize = pqclean768::EK_SIZE;
pub const MLKEM768_DK_SIZE: usize = pqclean768::DK_SIZE;
pub const MLKEM768_CT_SIZE: usize = pqclean768::CT_SIZE;
pub const MLKEM768_SS_SIZE: usize = 32;
pub const MLKEM_SEED_SIZE: usize = 32;

pub type EncapsKey = [u8; MLKEM768_EK_SIZE];
pub type DecapsKey = [u8; MLKEM768_DK_SIZE];
pub type Ciphertext = [u8; MLKEM768_CT_SIZE];
pub type SharedSecret = [u8; MLKEM768_SS_SIZE];

fn derive_keypair_coins(seed: &[u8; MLKEM_SEED_SIZE]) -> [u8; 64] {
    let mut out = [0u8; 64];
    shake256(&mut out, seed);
    out
}

pub fn keygen(seed: &[u8; MLKEM_SEED_SIZE]) -> Result<(EncapsKey, DecapsKey)> {
    let coins = derive_keypair_coins(seed);
    let mut ek = [0u8; MLKEM768_EK_SIZE];
    let mut dk = [0u8; MLKEM768_DK_SIZE];
    pqclean768::crypto_kem_keypair_derand(&mut ek, &mut dk, &coins);
    Ok((ek, dk))
}

pub fn encaps(ek: &EncapsKey, m: &[u8; MLKEM_SEED_SIZE]) -> Result<(Ciphertext, SharedSecret)> {
    let mut ct = [0u8; MLKEM768_CT_SIZE];
    let mut ss = [0u8; MLKEM768_SS_SIZE];
    pqclean768::crypto_kem_enc_derand(&mut ct, &mut ss, ek, m);
    Ok((ct, ss))
}

pub fn decaps(ct: &Ciphertext, dk: &DecapsKey) -> Result<SharedSecret> {
    let mut ss = SharedSecret::default();
    pqclean768::crypto_kem_dec(&mut ss, ct, dk);
    Ok(ss)
}

pub fn keygen_random() -> Result<(EncapsKey, DecapsKey)> {
    let mut seed = [0u8; MLKEM_SEED_SIZE];
    fill_random(&mut seed)?;
    keygen(&seed)
}

pub fn encaps_random(ek: &EncapsKey) -> Result<(Ciphertext, SharedSecret)> {
    let mut m = [0u8; MLKEM_SEED_SIZE];
    fill_random(&mut m)?;
    encaps(ek, &m)
}

fn fill_random(buf: &mut [u8]) -> Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .map_err(|_| Error::Crypto)?
        .read_exact(buf)
        .map_err(|_| Error::Crypto)
}

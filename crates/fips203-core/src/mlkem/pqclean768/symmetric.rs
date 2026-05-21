use crate::fips202::{sha3_256, sha3_512, shake256, Shake128Ctx, Shake256Inc, SHAKE128_RATE};

use super::params::{KYBER_CIPHERTEXTBYTES, KYBER_SSBYTES, KYBER_SYMBYTES};

pub fn hash_h(out: &mut [u8; 32], input: &[u8]) {
    sha3_256(out, input);
}

pub fn hash_g(out: &mut [u8; 64], input: &[u8]) {
    sha3_512(out, input);
}

pub fn kyber_shake128_absorb(seed: &[u8; KYBER_SYMBYTES], x: u8, y: u8) -> Shake128Ctx {
    let mut ext = [0u8; KYBER_SYMBYTES + 2];
    ext[..KYBER_SYMBYTES].copy_from_slice(seed);
    ext[KYBER_SYMBYTES] = x;
    ext[KYBER_SYMBYTES + 1] = y;
    Shake128Ctx::absorb(&ext)
}

pub fn xof_squeezeblocks(out: &mut [u8], nblocks: usize, state: &mut Shake128Ctx) {
    state.squeeze_blocks(out, nblocks);
}

pub const XOF_BLOCKBYTES: usize = SHAKE128_RATE;

pub fn prf(out: &mut [u8], key: &[u8; KYBER_SYMBYTES], nonce: u8) {
    let mut ext = [0u8; KYBER_SYMBYTES + 1];
    ext[..KYBER_SYMBYTES].copy_from_slice(key);
    ext[KYBER_SYMBYTES] = nonce;
    shake256(out, &ext);
}

pub fn rkprf(out: &mut [u8; KYBER_SSBYTES], key: &[u8; KYBER_SYMBYTES], input: &[u8; KYBER_CIPHERTEXTBYTES]) {
    let mut inc = Shake256Inc::new();
    inc.rkprf(key, input, out);
}

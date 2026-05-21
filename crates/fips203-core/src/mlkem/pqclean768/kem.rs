use super::indcpa::{indcpa_dec, indcpa_enc, indcpa_keypair_derand};
use super::params::*;
use super::symmetric::{hash_g, hash_h, rkprf};
use super::verify::{cmov, verify};

pub fn crypto_kem_keypair_derand(ek: &mut [u8; EK_SIZE], dk: &mut [u8; DK_SIZE], coins: &[u8; 64]) {
    let (ek_indcpa, _) = ek.split_at_mut(KYBER_INDCPA_PUBLICKEYBYTES);
    let (dk_indcpa, dk_rest) = dk.split_at_mut(KYBER_INDCPA_SECRETKEYBYTES);
    indcpa_keypair_derand(
        ek_indcpa.try_into().unwrap(),
        dk_indcpa.try_into().unwrap(),
        coins[..KYBER_SYMBYTES].try_into().unwrap(),
    );
    dk_rest[..KYBER_PUBLICKEYBYTES].copy_from_slice(ek);
    hash_h(
        (&mut dk[DK_SIZE - 2 * KYBER_SYMBYTES..DK_SIZE - KYBER_SYMBYTES]).try_into().unwrap(),
        ek,
    );
    dk[DK_SIZE - KYBER_SYMBYTES..].copy_from_slice(&coins[KYBER_SYMBYTES..]);
}

pub fn crypto_kem_enc_derand(
    ct: &mut [u8; CT_SIZE],
    ss: &mut [u8; KYBER_SSBYTES],
    ek: &[u8; EK_SIZE],
    coins: &[u8; KYBER_SYMBYTES],
) {
    let mut buf = [0u8; 2 * KYBER_SYMBYTES];
    let mut kr = [0u8; 2 * KYBER_SYMBYTES];
    buf[..KYBER_SYMBYTES].copy_from_slice(coins);
    hash_h((&mut buf[KYBER_SYMBYTES..]).try_into().unwrap(), ek);
    hash_g(&mut kr, &buf);
    indcpa_enc(
        ct,
        buf[..KYBER_SYMBYTES].try_into().unwrap(),
        ek[..KYBER_INDCPA_PUBLICKEYBYTES].try_into().unwrap(),
        kr[KYBER_SYMBYTES..].try_into().unwrap(),
    );
    ss.copy_from_slice(&kr[..KYBER_SYMBYTES]);
}

pub fn crypto_kem_dec(ss: &mut [u8; KYBER_SSBYTES], ct: &[u8; CT_SIZE], dk: &[u8; DK_SIZE]) {
    let mut buf = [0u8; 2 * KYBER_SYMBYTES];
    let mut kr = [0u8; 2 * KYBER_SYMBYTES];
    let mut cmp = [0u8; KYBER_CIPHERTEXTBYTES + KYBER_SSBYTES];
    let pk = &dk[KYBER_INDCPA_SECRETKEYBYTES..KYBER_INDCPA_SECRETKEYBYTES + KYBER_PUBLICKEYBYTES];

    indcpa_dec(
        (&mut buf[..KYBER_SYMBYTES]).try_into().unwrap(),
        ct,
        dk[..KYBER_INDCPA_SECRETKEYBYTES].try_into().unwrap(),
    );
    buf[KYBER_SYMBYTES..].copy_from_slice(&dk[DK_SIZE - 2 * KYBER_SYMBYTES..DK_SIZE - KYBER_SYMBYTES]);
    hash_g(&mut kr, &buf);
    indcpa_enc(
        (&mut cmp[..KYBER_CIPHERTEXTBYTES]).try_into().unwrap(),
        buf[..KYBER_SYMBYTES].try_into().unwrap(),
        pk[..KYBER_INDCPA_PUBLICKEYBYTES].try_into().unwrap(),
        kr[KYBER_SYMBYTES..].try_into().unwrap(),
    );
    cmp[KYBER_CIPHERTEXTBYTES..].copy_from_slice(&kr[..KYBER_SYMBYTES]);

    let fail = verify(ct, &cmp[..KYBER_CIPHERTEXTBYTES]);
    rkprf(
        ss,
        dk[DK_SIZE - KYBER_SYMBYTES..].try_into().unwrap(),
        ct,
    );
    cmov(ss, &kr[..KYBER_SYMBYTES], 1 - fail);
}

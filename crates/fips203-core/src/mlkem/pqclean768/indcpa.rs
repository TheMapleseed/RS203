use super::params::*;
use super::poly::Poly;
use super::polyvec::PolyVec;
use super::symmetric::{hash_g, kyber_shake128_absorb, xof_squeezeblocks, XOF_BLOCKBYTES};

fn rej_uniform(r: &mut [i16], buf: &[u8]) -> usize {
    let mut ctr = 0usize;
    let mut pos = 0usize;
    while ctr < KYBER_N && pos + 3 <= buf.len() {
        let val0 = (u16::from(buf[pos]) | (u16::from(buf[pos + 1]) << 8)) & 0xfff;
        let val1 = (u16::from(buf[pos + 1]) >> 4 | (u16::from(buf[pos + 2]) << 4)) & 0xfff;
        pos += 3;
        if val0 < KYBER_Q as u16 {
            r[ctr] = val0 as i16;
            ctr += 1;
        }
        if ctr < KYBER_N && val1 < KYBER_Q as u16 {
            r[ctr] = val1 as i16;
            ctr += 1;
        }
    }
    ctr
}

fn gen_matrix(a: &mut [PolyVec; KYBER_K], seed: &[u8; KYBER_SYMBYTES], transposed: bool) {
    const GEN_NBLOCKS: usize = (12 * KYBER_N / 8 * (1 << 12) / KYBER_Q as usize + XOF_BLOCKBYTES - 1)
        / XOF_BLOCKBYTES;
    let mut buf = [0u8; GEN_NBLOCKS * XOF_BLOCKBYTES];
    for i in 0..KYBER_K {
        for j in 0..KYBER_K {
            let (x, y) = if transposed { (i as u8, j as u8) } else { (j as u8, i as u8) };
            let mut state = kyber_shake128_absorb(seed, x, y);
            xof_squeezeblocks(&mut buf, GEN_NBLOCKS, &mut state);
            let mut ctr = rej_uniform(&mut a[i].vec[j].coeffs, &buf);
            while ctr < KYBER_N {
                xof_squeezeblocks(&mut buf[..XOF_BLOCKBYTES], 1, &mut state);
                ctr += rej_uniform(&mut a[i].vec[j].coeffs[ctr..], &buf[..XOF_BLOCKBYTES]);
            }
        }
    }
}

fn pack_pk(pk: &mut [u8; KYBER_INDCPA_PUBLICKEYBYTES], pv: &PolyVec, seed: &[u8; KYBER_SYMBYTES]) {
    let (poly, tail) = pk.split_at_mut(KYBER_POLYVECBYTES);
    pv.tobytes(poly.try_into().unwrap());
    tail.copy_from_slice(seed);
}

fn unpack_pk(
    pkpv: &mut PolyVec,
    seed: &mut [u8; KYBER_SYMBYTES],
    packed: &[u8; KYBER_INDCPA_PUBLICKEYBYTES],
) {
    let (poly, tail) = packed.split_at(KYBER_POLYVECBYTES);
    PolyVec::frombytes(pkpv, poly.try_into().unwrap());
    seed.copy_from_slice(tail);
}

fn pack_sk(sk: &mut [u8; KYBER_INDCPA_SECRETKEYBYTES], sv: &PolyVec) {
    sv.tobytes(sk);
}

fn unpack_sk(skpv: &mut PolyVec, packed: &[u8; KYBER_INDCPA_SECRETKEYBYTES]) {
    PolyVec::frombytes(skpv, packed);
}

fn pack_ct(ct: &mut [u8; KYBER_INDCPA_BYTES], b: &PolyVec, v: &Poly) {
    let (bc, vc) = ct.split_at_mut(KYBER_POLYVECCOMPRESSEDBYTES);
    b.compress(bc.try_into().unwrap());
    v.compress(vc.try_into().unwrap());
}

fn unpack_ct(b: &mut PolyVec, v: &mut Poly, c: &[u8; KYBER_INDCPA_BYTES]) {
    let (bc, vc) = c.split_at(KYBER_POLYVECCOMPRESSEDBYTES);
    PolyVec::decompress(b, bc.try_into().unwrap());
    Poly::decompress(v, vc.try_into().unwrap());
}

pub fn indcpa_keypair_derand(
    pk: &mut [u8; KYBER_INDCPA_PUBLICKEYBYTES],
    sk: &mut [u8; KYBER_INDCPA_SECRETKEYBYTES],
    coins: &[u8; KYBER_SYMBYTES],
) {
    let mut buf = [0u8; 2 * KYBER_SYMBYTES];
    buf[..KYBER_SYMBYTES].copy_from_slice(coins);
    buf[KYBER_SYMBYTES] = KYBER_K as u8;
    let mut g_in = [0u8; KYBER_SYMBYTES + 1];
    g_in[..KYBER_SYMBYTES].copy_from_slice(coins);
    g_in[KYBER_SYMBYTES] = KYBER_K as u8;
    hash_g(&mut buf, &g_in);
    let publicseed: [u8; KYBER_SYMBYTES] = buf[..KYBER_SYMBYTES].try_into().unwrap();
    let noiseseed: [u8; KYBER_SYMBYTES] = buf[KYBER_SYMBYTES..2 * KYBER_SYMBYTES].try_into().unwrap();

    let mut a = [PolyVec::default(); KYBER_K];
    gen_matrix(&mut a, &publicseed, false);

    let mut skpv = PolyVec::default();
    let mut e = PolyVec::default();
    let mut pkpv = PolyVec::default();
    let mut nonce = 0u8;
    for i in 0..KYBER_K {
        skpv.vec[i].getnoise_eta1(&noiseseed, nonce);
        nonce += 1;
    }
    for i in 0..KYBER_K {
        e.vec[i].getnoise_eta1(&noiseseed, nonce);
        nonce += 1;
    }
    skpv.ntt();
    e.ntt();
    for i in 0..KYBER_K {
        let mut acc = Poly::default();
        PolyVec::basemul_acc_montgomery(&mut acc, &a[i], &skpv);
        pkpv.vec[i] = acc;
        pkpv.vec[i].tomont();
    }
    let pk_copy = pkpv;
    pkpv.add(&pk_copy, &e);
    pkpv.reduce();
    pack_sk(sk, &skpv);
    pack_pk(pk, &pkpv, &publicseed);
}

pub fn indcpa_enc(
    ct: &mut [u8; KYBER_INDCPA_BYTES],
    m: &[u8; KYBER_INDCPA_MSGBYTES],
    pk: &[u8; KYBER_INDCPA_PUBLICKEYBYTES],
    coins: &[u8; KYBER_SYMBYTES],
) {
    let mut seed = [0u8; KYBER_SYMBYTES];
    let mut pkpv = PolyVec::default();
    unpack_pk(&mut pkpv, &mut seed, pk);
    let mut k = Poly::default();
    Poly::frommsg(&mut k, m);
    let mut at = [PolyVec::default(); KYBER_K];
    gen_matrix(&mut at, &seed, true);
    let mut sp = PolyVec::default();
    let mut ep = PolyVec::default();
    let mut epp = Poly::default();
    let mut nonce = 0u8;
    for i in 0..KYBER_K {
        sp.vec[i].getnoise_eta1(coins, nonce);
        nonce += 1;
    }
    for i in 0..KYBER_K {
        ep.vec[i].getnoise_eta2(coins, nonce);
        nonce += 1;
    }
    epp.getnoise_eta2(coins, nonce);
    sp.ntt();
    let mut b = PolyVec::default();
    for i in 0..KYBER_K {
        let mut acc = Poly::default();
        PolyVec::basemul_acc_montgomery(&mut acc, &at[i], &sp);
        b.vec[i] = acc;
    }
    let mut v = Poly::default();
    PolyVec::basemul_acc_montgomery(&mut v, &pkpv, &sp);
    b.invntt_tomont();
    v.invntt_tomont();
    let b_copy = b;
    b.add(&b_copy, &ep);
    let v_copy = v;
    v.add(&v_copy, &epp);
    let v_copy2 = v;
    v.add(&v_copy2, &k);
    b.reduce();
    v.reduce();
    pack_ct(ct, &b, &v);
}

pub fn indcpa_dec(
    m: &mut [u8; KYBER_INDCPA_MSGBYTES],
    ct: &[u8; KYBER_INDCPA_BYTES],
    sk: &[u8; KYBER_INDCPA_SECRETKEYBYTES],
) {
    let mut b = PolyVec::default();
    let mut v = Poly::default();
    unpack_ct(&mut b, &mut v, ct);
    let mut skpv = PolyVec::default();
    unpack_sk(&mut skpv, sk);
    b.ntt();
    let mut mp = Poly::default();
    PolyVec::basemul_acc_montgomery(&mut mp, &skpv, &b);
    mp.invntt_tomont();
    let mp_copy = mp;
    mp.sub(&v, &mp_copy);
    mp.reduce();
    mp.tomsg(m);
}

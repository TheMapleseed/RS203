
use super::cbd::{poly_cbd_eta1, poly_cbd_eta2};
use super::ntt::{basemul, invntt, ntt, ZETAS};
use super::params::*;
use super::reduce::{barrett_reduce, montgomery_reduce};
use super::symmetric::prf;
use super::verify::cmov_i16;

#[derive(Clone, Copy)]
pub struct Poly {
    pub coeffs: [i16; KYBER_N],
}

impl Default for Poly {
    fn default() -> Self {
        Self { coeffs: [0; KYBER_N] }
    }
}

impl Poly {
    pub fn compress(&self, r: &mut [u8; KYBER_POLYCOMPRESSEDBYTES]) {
        let mut rp = 0usize;
        for i in 0..KYBER_N / 8 {
            let mut t = [0u8; 8];
            for j in 0..8 {
                let mut u = self.coeffs[8 * i + j];
                u += (u >> 15) & KYBER_Q as i16;
                let d0 = (u as u32) << 4;
                let d0 = d0.wrapping_add(1665).wrapping_mul(80635) >> 28;
                t[j] = (d0 & 0xf) as u8;
            }
            r[rp] = t[0] | (t[1] << 4);
            r[rp + 1] = t[2] | (t[3] << 4);
            r[rp + 2] = t[4] | (t[5] << 4);
            r[rp + 3] = t[6] | (t[7] << 4);
            rp += 4;
        }
    }

    pub fn decompress(r: &mut Self, a: &[u8; KYBER_POLYCOMPRESSEDBYTES]) {
        let mut ap = 0usize;
        for i in 0..KYBER_N / 2 {
            r.coeffs[2 * i] = ((((a[ap] & 15) as u32 * KYBER_Q as u32) + 8) >> 4) as i16;
            r.coeffs[2 * i + 1] = ((((a[ap] >> 4) as u32 * KYBER_Q as u32) + 8) >> 4) as i16;
            ap += 1;
        }
    }

    pub fn tobytes(&self, r: &mut [u8; KYBER_POLYBYTES]) {
        for i in 0..KYBER_N / 2 {
            let mut t0 = self.coeffs[2 * i];
            t0 += (t0 >> 15) & KYBER_Q as i16;
            let mut t1 = self.coeffs[2 * i + 1];
            t1 += (t1 >> 15) & KYBER_Q as i16;
            r[3 * i] = t0 as u8;
            r[3 * i + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
            r[3 * i + 2] = (t1 >> 4) as u8;
        }
    }

    pub fn frombytes(r: &mut Self, a: &[u8; KYBER_POLYBYTES]) {
        for i in 0..KYBER_N / 2 {
            r.coeffs[2 * i] = ((a[3 * i] as u16) | ((a[3 * i + 1] as u16) << 8)) as i16 & 0xfff;
            r.coeffs[2 * i + 1] =
                ((a[3 * i + 1] >> 4) as i16) | (((a[3 * i + 2] as i16) << 4) & 0xfff);
        }
    }

    pub fn frommsg(r: &mut Self, msg: &[u8; KYBER_INDCPA_MSGBYTES]) {
        for i in 0..KYBER_N / 8 {
            for j in 0..8 {
                r.coeffs[8 * i + j] = 0;
                let bit = (msg[i] >> j) & 1;
                let v = ((KYBER_Q + 1) / 2) as i16;
                cmov_i16(&mut r.coeffs[8 * i + j], v, bit as u16);
            }
        }
    }

    pub fn tomsg(&self, msg: &mut [u8; KYBER_INDCPA_MSGBYTES]) {
        for i in 0..KYBER_N / 8 {
            msg[i] = 0;
            for j in 0..8 {
                let mut t = self.coeffs[8 * i + j] as u32;
                t = t << 1;
                t = t.wrapping_add(1665).wrapping_mul(80635) >> 28;
                msg[i] |= ((t & 1) as u8) << j;
            }
        }
    }

    pub fn getnoise_eta1(&mut self, seed: &[u8; KYBER_SYMBYTES], nonce: u8) {
        let mut buf = [0u8; KYBER_ETA1 * KYBER_N / 4];
        prf(&mut buf, &seed, nonce);
        poly_cbd_eta1(self, &buf);
    }

    pub fn getnoise_eta2(&mut self, seed: &[u8; KYBER_SYMBYTES], nonce: u8) {
        let mut buf = [0u8; KYBER_ETA2 * KYBER_N / 4];
        prf(&mut buf, &seed, nonce);
        poly_cbd_eta2(self, &buf);
    }

    pub fn poly_ntt(&mut self) {
        ntt(&mut self.coeffs);
        self.reduce();
    }

    pub fn invntt_tomont(&mut self) {
        invntt(&mut self.coeffs);
    }

    pub fn basemul_montgomery(&mut self, a: &Poly, b: &Poly) {
        for i in 0..KYBER_N / 4 {
            let mut r0 = [0i16; 2];
            let mut r1 = [0i16; 2];
            let a0 = [a.coeffs[4 * i], a.coeffs[4 * i + 1]];
            let b0 = [b.coeffs[4 * i], b.coeffs[4 * i + 1]];
            basemul(&mut r0, &a0, &b0, ZETAS[64 + i]);
            let a1 = [a.coeffs[4 * i + 2], a.coeffs[4 * i + 3]];
            let b1 = [b.coeffs[4 * i + 2], b.coeffs[4 * i + 3]];
            basemul(&mut r1, &a1, &b1, -ZETAS[64 + i]);
            self.coeffs[4 * i] = r0[0];
            self.coeffs[4 * i + 1] = r0[1];
            self.coeffs[4 * i + 2] = r1[0];
            self.coeffs[4 * i + 3] = r1[1];
        }
    }

    pub fn tomont(&mut self) {
        let f = ((1u64 << 32) % KYBER_Q as u64) as i32;
        for c in &mut self.coeffs {
            *c = montgomery_reduce(*c as i32 * f);
        }
    }

    pub fn reduce(&mut self) {
        for c in &mut self.coeffs {
            *c = barrett_reduce(*c);
        }
    }

    pub fn add(&mut self, a: &Poly, b: &Poly) {
        for i in 0..KYBER_N {
            self.coeffs[i] = a.coeffs[i] + b.coeffs[i];
        }
    }

    pub fn sub(&mut self, a: &Poly, b: &Poly) {
        for i in 0..KYBER_N {
            self.coeffs[i] = a.coeffs[i] - b.coeffs[i];
        }
    }
}

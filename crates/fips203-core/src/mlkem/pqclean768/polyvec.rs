use super::params::*;
use super::poly::Poly;

#[derive(Clone, Copy, Default)]
pub struct PolyVec {
    pub vec: [Poly; KYBER_K],
}

impl PolyVec {
    pub fn compress(&self, r: &mut [u8; KYBER_POLYVECCOMPRESSEDBYTES]) {
        let mut rp = 0usize;
        for i in 0..KYBER_K {
            for j in 0..KYBER_N / 4 {
                let mut t = [0u16; 4];
                for k in 0..4 {
                    let mut v = self.vec[i].coeffs[4 * j + k];
                    v += (v >> 15) & KYBER_Q as i16;
                    let d0 = (v as u64) << 10;
                    let d0 = (d0 + 1665).wrapping_mul(1290167) >> 32;
                    t[k] = (d0 & 0x3ff) as u16;
                }
                r[rp] = t[0] as u8;
                r[rp + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
                r[rp + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
                r[rp + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
                r[rp + 4] = (t[3] >> 2) as u8;
                rp += 5;
            }
        }
    }

    pub fn decompress(r: &mut Self, a: &[u8; KYBER_POLYVECCOMPRESSEDBYTES]) {
        let mut ap = 0usize;
        for i in 0..KYBER_K {
            for j in 0..KYBER_N / 4 {
                let t0 = u16::from(a[ap]) | (u16::from(a[ap + 1]) << 8);
                let t1 = (u16::from(a[ap + 1]) >> 2) | (u16::from(a[ap + 2]) << 6);
                let t2 = (u16::from(a[ap + 2]) >> 4) | (u16::from(a[ap + 3]) << 4);
                let t3 = (u16::from(a[ap + 3]) >> 6) | (u16::from(a[ap + 4]) << 2);
                ap += 5;
                let ts = [t0, t1, t2, t3];
                for k in 0..4 {
                    r.vec[i].coeffs[4 * j + k] =
                        ((u32::from(ts[k] & 0x3ff) * KYBER_Q as u32 + 512) >> 10) as i16;
                }
            }
        }
    }

    pub fn tobytes(&self, r: &mut [u8; KYBER_POLYVECBYTES]) {
        for i in 0..KYBER_K {
            let mut tmp = [0u8; KYBER_POLYBYTES];
            self.vec[i].tobytes(&mut tmp);
            r[i * KYBER_POLYBYTES..(i + 1) * KYBER_POLYBYTES].copy_from_slice(&tmp);
        }
    }

    pub fn frombytes(r: &mut Self, a: &[u8; KYBER_POLYVECBYTES]) {
        for i in 0..KYBER_K {
            let chunk: [u8; KYBER_POLYBYTES] = a[i * KYBER_POLYBYTES..(i + 1) * KYBER_POLYBYTES]
                .try_into()
                .unwrap();
            Poly::frombytes(&mut r.vec[i], &chunk);
        }
    }

    pub fn ntt(&mut self) {
        for v in &mut self.vec {
            v.poly_ntt();
        }
    }

    pub fn invntt_tomont(&mut self) {
        for v in &mut self.vec {
            v.invntt_tomont();
        }
    }

    pub fn basemul_acc_montgomery(r: &mut Poly, a: &PolyVec, b: &PolyVec) {
        r.basemul_montgomery(&a.vec[0], &b.vec[0]);
        for i in 1..KYBER_K {
            let mut t = Poly::default();
            t.basemul_montgomery(&a.vec[i], &b.vec[i]);
            for j in 0..KYBER_N {
                r.coeffs[j] += t.coeffs[j];
            }
        }
        r.reduce();
    }

    pub fn reduce(&mut self) {
        for v in &mut self.vec {
            v.reduce();
        }
    }

    pub fn add(&mut self, a: &PolyVec, b: &PolyVec) {
        for i in 0..KYBER_K {
            self.vec[i].add(&a.vec[i], &b.vec[i]);
        }
    }
}

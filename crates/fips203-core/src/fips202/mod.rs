//! FIPS 202 — pure Rust (PQClean-compatible).

mod fips202_keccak_perm;

use fips202_keccak_perm::keccak_f1600;

pub const SHAKE128_RATE: usize = 168;
pub const SHAKE256_RATE: usize = 136;
pub const SHA3_256_RATE: usize = 136;
pub const SHA3_512_RATE: usize = 72;

fn load64(x: &[u8]) -> u64 {
    let mut r = 0u64;
    for (i, &b) in x.iter().enumerate().take(8) {
        r |= u64::from(b) << (8 * i);
    }
    r
}

fn store64(x: &mut [u8], u: u64) {
    for (i, b) in x.iter_mut().enumerate().take(8) {
        *b = (u >> (8 * i)) as u8;
    }
}

fn keccak_absorb(s: &mut [u64; 25], rate: usize, input: &[u8], delim: u8) {
    s.fill(0);
    let mut m = input;
    while m.len() >= rate {
        for i in 0..rate / 8 {
            s[i] ^= load64(&m[i * 8..i * 8 + 8]);
        }
        keccak_f1600(s);
        m = &m[rate..];
    }
    let mut t = [0u8; 200];
    t[..m.len()].copy_from_slice(m);
    t[m.len()] = delim;
    t[rate - 1] |= 0x80;
    for i in 0..rate / 8 {
        s[i] ^= load64(&t[i * 8..i * 8 + 8]);
    }
}

fn keccak_squeezeblocks(out: &mut [u8], nblocks: usize, s: &mut [u64; 25], rate: usize) {
    for block in 0..nblocks {
        keccak_f1600(s);
        for i in 0..rate / 8 {
            store64(&mut out[block * rate + i * 8..block * rate + i * 8 + 8], s[i]);
        }
    }
}

pub fn shake256(out: &mut [u8], input: &[u8]) {
    let rate = SHAKE256_RATE;
    let mut s = [0u64; 25];
    keccak_absorb(&mut s, rate, input, 0x1f);
    let nb = out.len() / rate;
    keccak_squeezeblocks(&mut out[..nb * rate], nb, &mut s, rate);
    let tail = out.len() - nb * rate;
    if tail > 0 {
        let mut t = [0u8; SHAKE256_RATE];
        keccak_squeezeblocks(&mut t, 1, &mut s, rate);
        out[nb * rate..].copy_from_slice(&t[..tail]);
    }
}

pub fn sha3_256(out: &mut [u8; 32], input: &[u8]) {
    let mut s = [0u64; 25];
    keccak_absorb(&mut s, SHA3_256_RATE, input, 0x06);
    let mut t = [0u8; SHA3_256_RATE];
    keccak_squeezeblocks(&mut t, 1, &mut s, SHA3_256_RATE);
    out.copy_from_slice(&t[..32]);
}

pub fn sha3_512(out: &mut [u8; 64], input: &[u8]) {
    let mut s = [0u64; 25];
    keccak_absorb(&mut s, SHA3_512_RATE, input, 0x06);
    let mut t = [0u8; SHA3_512_RATE];
    keccak_squeezeblocks(&mut t, 1, &mut s, SHA3_512_RATE);
    out.copy_from_slice(&t[..64]);
}

pub struct Shake128Ctx {
    pub s: [u64; 25],
    pub rate: usize,
}

impl Shake128Ctx {
    pub fn absorb(input: &[u8]) -> Self {
        let mut s = [0u64; 25];
        keccak_absorb(&mut s, SHAKE128_RATE, input, 0x1f);
        Self {
            s,
            rate: SHAKE128_RATE,
        }
    }

    pub fn squeeze_blocks(&mut self, out: &mut [u8], nblocks: usize) {
        keccak_squeezeblocks(out, nblocks, &mut self.s, self.rate);
    }
}

pub struct Shake256Inc {
    s: [u64; 26],
}

impl Shake256Inc {
    pub fn new() -> Self {
        Self { s: [0; 26] }
    }

    fn absorb(&mut self, input: &[u8], rate: usize) {
        let mut pos = 0usize;
        let mut left = input.len();
        while left > 0 {
            let avail = rate - self.s[25] as usize;
            if left >= avail {
                for i in 0..avail {
                    let idx = self.s[25] as usize + i;
                    self.s[idx >> 3] ^= u64::from(input[pos + i]) << (8 * (idx & 7));
                }
                pos += avail;
                left -= avail;
                self.s[25] = 0;
                keccak_f1600(&mut self.s[..25]);
            } else {
                for i in 0..left {
                    let idx = self.s[25] as usize + i;
                    self.s[idx >> 3] ^= u64::from(input[pos + i]) << (8 * (idx & 7));
                }
                self.s[25] += left as u64;
                break;
            }
        }
    }

    fn finalize(&mut self, rate: usize, p: u8) {
        let idx = self.s[25] as usize;
        self.s[idx >> 3] ^= u64::from(p) << (8 * (idx & 7));
        self.s[(rate - 1) >> 3] ^= 1u64 << (8 * ((rate - 1) & 7));
        self.s[25] = 0;
    }

    fn squeeze(&mut self, out: &mut [u8], rate: usize) {
        let mut done = 0usize;
        while done < out.len() {
            if self.s[25] > 0 {
                let avail = (self.s[25] as usize).min(out.len() - done);
                for i in 0..avail {
                    let pos = rate - self.s[25] as usize + i;
                    out[done + i] = (self.s[pos >> 3] >> (8 * (pos & 7))) as u8;
                }
                done += avail;
                self.s[25] -= avail as u64;
            }
            if done < out.len() {
                keccak_f1600(&mut self.s[..25]);
                let take = (out.len() - done).min(rate);
                for j in 0..take {
                    out[done + j] = (self.s[j >> 3] >> (8 * (j & 7))) as u8;
                }
                done += take;
                self.s[25] = (rate - take) as u64;
            }
        }
    }

    pub fn rkprf(&mut self, key: &[u8], ct: &[u8], out: &mut [u8; 32]) {
        self.s = [0; 26];
        self.absorb(key, SHAKE256_RATE);
        self.absorb(ct, SHAKE256_RATE);
        self.finalize(SHAKE256_RATE, 0x1f);
        self.squeeze(out, SHAKE256_RATE);
    }
}

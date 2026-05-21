include!("ntt_zetas.rs");

use super::reduce::{barrett_reduce, montgomery_reduce};

fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce(a as i32 * b as i32)
}

pub fn ntt(r: &mut [i16; 256]) {
    let mut k = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = ZETAS[k];
            k += 1;
            let end = start + len;
            for j in start..end {
                let t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] += t;
            }
            start = end + len;
        }
        len >>= 1;
    }
}

pub fn invntt(r: &mut [i16; 256]) {
    const F: i16 = 1441;
    let mut k = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = ZETAS[k];
            k -= 1;
            let end = start + len;
            for j in start..end {
                let t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = r[j + len] - t;
                r[j + len] = fqmul(zeta, r[j + len]);
            }
            start = end + len;
        }
        len <<= 1;
    }
    for c in r.iter_mut() {
        *c = fqmul(*c, F);
    }
}

pub fn basemul(r: &mut [i16; 2], a: &[i16; 2], b: &[i16; 2], zeta: i16) {
    r[0] = fqmul(a[1], b[1]);
    r[0] = fqmul(r[0], zeta);
    r[0] += fqmul(a[0], b[0]);
    r[1] = fqmul(a[0], b[1]);
    r[1] += fqmul(a[1], b[0]);
}

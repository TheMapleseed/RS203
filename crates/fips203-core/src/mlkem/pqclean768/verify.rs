pub fn verify(a: &[u8], b: &[u8]) -> u8 {
    let mut r = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        r |= x ^ y;
    }
    ((-(r as i64)) >> 63) as u8
}

pub fn cmov(r: &mut [u8], x: &[u8], b: u8) {
    let mask = (-(b as i16)) as u8;
    for (ri, xi) in r.iter_mut().zip(x.iter()) {
        *ri ^= mask & (*ri ^ xi);
    }
}

pub fn cmov_i16(r: &mut i16, v: i16, b: u16) {
    let mask = (-(b as i16)) as i16;
    *r ^= mask & (*r ^ v);
}

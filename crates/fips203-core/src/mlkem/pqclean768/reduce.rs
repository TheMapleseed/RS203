use super::params::KYBER_Q;

pub const MONT: i16 = -1044;
pub const QINV: i16 = -3327;

pub fn montgomery_reduce(a: i32) -> i16 {
    let t = (a as i16).wrapping_mul(QINV);
    ((a - (t as i32) * KYBER_Q) >> 16) as i16
}

pub fn barrett_reduce(mut a: i16) -> i16 {
    const V: i32 = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;
    let t = ((V * i32::from(a) + (1 << 25)) >> 26) as i16;
    a -= (t * KYBER_Q as i16);
    a
}

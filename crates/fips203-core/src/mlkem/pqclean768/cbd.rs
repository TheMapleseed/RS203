use super::poly::Poly;
use super::params::KYBER_N;

fn load32_littleendian(x: &[u8; 4]) -> u32 {
    u32::from(x[0]) | (u32::from(x[1]) << 8) | (u32::from(x[2]) << 16) | (u32::from(x[3]) << 24)
}

fn cbd2(r: &mut Poly, buf: &[u8]) {
    for i in 0..KYBER_N / 8 {
        let chunk: [u8; 4] = buf[4 * i..4 * i + 4].try_into().unwrap();
        let t = load32_littleendian(&chunk);
        let d = (t & 0x5555_5555).wrapping_add((t >> 1) & 0x5555_5555);
        for j in 0..8 {
            let a = ((d >> (4 * j)) & 0x3) as i16;
            let b = ((d >> (4 * j + 2)) & 0x3) as i16;
            r.coeffs[8 * i + j] = a - b;
        }
    }
}

pub fn poly_cbd_eta1(r: &mut Poly, buf: &[u8]) {
    cbd2(r, buf);
}

pub fn poly_cbd_eta2(r: &mut Poly, buf: &[u8]) {
    cbd2(r, buf);
}

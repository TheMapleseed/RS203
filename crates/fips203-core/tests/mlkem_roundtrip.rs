use fips203_core::{decaps, encaps, keygen};

#[test]
fn mlkem_deterministic_roundtrip() {
    let seed = [7u8; 32];
    let m = [9u8; 32];
    let (ek, dk) = keygen(&seed).expect("keygen");
    let (ct, ss1) = encaps(&ek, &m).expect("encaps");
    let ss2 = decaps(&ct, &dk).expect("decaps");
    assert_eq!(ss1, ss2);
}

// PQClean fips202.c KeccakF1600_StatePermute
#[inline(always)]
fn rol(x: u64, o: u32) -> u64 { x.rotate_left(o % 64) }
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];
pub fn keccak_f1600(state: &mut [u64]) {
    let mut Aba: u64;
    let mut Abe: u64;
    let mut Abi: u64;
    let mut Abo: u64;
    let mut Abu: u64;
    let mut Aga: u64;
    let mut Age: u64;
    let mut Agi: u64;
    let mut Ago: u64;
    let mut Agu: u64;
    let mut Aka: u64;
    let mut Ake: u64;
    let mut Aki: u64;
    let mut Ako: u64;
    let mut Aku: u64;
    let mut Ama: u64;
    let mut Ame: u64;
    let mut Ami: u64;
    let mut Amo: u64;
    let mut Amu: u64;
    let mut Asa: u64;
    let mut Ase: u64;
    let mut Asi: u64;
    let mut Aso: u64;
    let mut Asu: u64;
    let mut BCa: u64;
    let mut BCe: u64;
    let mut BCi: u64;
    let mut BCo: u64;
    let mut BCu: u64;
    let mut Da: u64;
    let mut De: u64;
    let mut Di: u64;
    let mut Do: u64;
    let mut Du: u64;
    let mut Eba: u64;
    let mut Ebe: u64;
    let mut Ebi: u64;
    let mut Ebo: u64;
    let mut Ebu: u64;
    let mut Ega: u64;
    let mut Ege: u64;
    let mut Egi: u64;
    let mut Ego: u64;
    let mut Egu: u64;
    let mut Eka: u64;
    let mut Eke: u64;
    let mut Eki: u64;
    let mut Eko: u64;
    let mut Eku: u64;
    let mut Ema: u64;
    let mut Eme: u64;
    let mut Emi: u64;
    let mut Emo: u64;
    let mut Emu: u64;
    let mut Esa: u64;
    let mut Ese: u64;
    let mut Esi: u64;
    let mut Eso: u64;
    let mut Esu: u64;
    // copyFromState(A, state)
    Aba = state[0];
    Abe = state[1];
    Abi = state[2];
    Abo = state[3];
    Abu = state[4];
    Aga = state[5];
    Age = state[6];
    Agi = state[7];
    Ago = state[8];
    Agu = state[9];
    Aka = state[10];
    Ake = state[11];
    Aki = state[12];
    Ako = state[13];
    Aku = state[14];
    Ama = state[15];
    Ame = state[16];
    Ami = state[17];
    Amo = state[18];
    Amu = state[19];
    Asa = state[20];
    Ase = state[21];
    Asi = state[22];
    Aso = state[23];
    Asu = state[24];
    for round in (0..24).step_by(2) {
    //    prepareTheta
    BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
    BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
    BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
    BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
    BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
    // thetaRhoPiChiIotaPrepareTheta(round  , A, E)
    Da = BCu ^ rol(BCe, 1);
    De = BCa ^ rol(BCi, 1);
    Di = BCe ^ rol(BCo, 1);
    Do = BCi ^ rol(BCu, 1);
    Du = BCo ^ rol(BCa, 1);
    Aba ^= Da;
    BCa = Aba;
    Age ^= De;
    BCe = rol(Age, 44);
    Aki ^= Di;
    BCi = rol(Aki, 43);
    Amo ^= Do;
    BCo = rol(Amo, 21);
    Asu ^= Du;
    BCu = rol(Asu, 14);
    Eba = BCa ^ ((!BCe) & BCi);
    Eba ^= RC[round];
    Ebe = BCe ^ ((!BCi) & BCo);
    Ebi = BCi ^ ((!BCo) & BCu);
    Ebo = BCo ^ ((!BCu) & BCa);
    Ebu = BCu ^ ((!BCa) & BCe);
    Abo ^= Do;
    BCa = rol(Abo, 28);
    Agu ^= Du;
    BCe = rol(Agu, 20);
    Aka ^= Da;
    BCi = rol(Aka, 3);
    Ame ^= De;
    BCo = rol(Ame, 45);
    Asi ^= Di;
    BCu = rol(Asi, 61);
    Ega = BCa ^ ((!BCe) & BCi);
    Ege = BCe ^ ((!BCi) & BCo);
    Egi = BCi ^ ((!BCo) & BCu);
    Ego = BCo ^ ((!BCu) & BCa);
    Egu = BCu ^ ((!BCa) & BCe);
    Abe ^= De;
    BCa = rol(Abe, 1);
    Agi ^= Di;
    BCe = rol(Agi, 6);
    Ako ^= Do;
    BCi = rol(Ako, 25);
    Amu ^= Du;
    BCo = rol(Amu, 8);
    Asa ^= Da;
    BCu = rol(Asa, 18);
    Eka = BCa ^ ((!BCe) & BCi);
    Eke = BCe ^ ((!BCi) & BCo);
    Eki = BCi ^ ((!BCo) & BCu);
    Eko = BCo ^ ((!BCu) & BCa);
    Eku = BCu ^ ((!BCa) & BCe);
    Abu ^= Du;
    BCa = rol(Abu, 27);
    Aga ^= Da;
    BCe = rol(Aga, 36);
    Ake ^= De;
    BCi = rol(Ake, 10);
    Ami ^= Di;
    BCo = rol(Ami, 15);
    Aso ^= Do;
    BCu = rol(Aso, 56);
    Ema = BCa ^ ((!BCe) & BCi);
    Eme = BCe ^ ((!BCi) & BCo);
    Emi = BCi ^ ((!BCo) & BCu);
    Emo = BCo ^ ((!BCu) & BCa);
    Emu = BCu ^ ((!BCa) & BCe);
    Abi ^= Di;
    BCa = rol(Abi, 62);
    Ago ^= Do;
    BCe = rol(Ago, 55);
    Aku ^= Du;
    BCi = rol(Aku, 39);
    Ama ^= Da;
    BCo = rol(Ama, 41);
    Ase ^= De;
    BCu = rol(Ase, 2);
    Esa = BCa ^ ((!BCe) & BCi);
    Ese = BCe ^ ((!BCi) & BCo);
    Esi = BCi ^ ((!BCo) & BCu);
    Eso = BCo ^ ((!BCu) & BCa);
    Esu = BCu ^ ((!BCa) & BCe);
    //    prepareTheta
    BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
    BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
    BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
    BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
    BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
    // thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
    Da = BCu ^ rol(BCe, 1);
    De = BCa ^ rol(BCi, 1);
    Di = BCe ^ rol(BCo, 1);
    Do = BCi ^ rol(BCu, 1);
    Du = BCo ^ rol(BCa, 1);
    Eba ^= Da;
    BCa = Eba;
    Ege ^= De;
    BCe = rol(Ege, 44);
    Eki ^= Di;
    BCi = rol(Eki, 43);
    Emo ^= Do;
    BCo = rol(Emo, 21);
    Esu ^= Du;
    BCu = rol(Esu, 14);
    Aba = BCa ^ ((!BCe) & BCi);
    Aba ^= RC[round + 1];
    Abe = BCe ^ ((!BCi) & BCo);
    Abi = BCi ^ ((!BCo) & BCu);
    Abo = BCo ^ ((!BCu) & BCa);
    Abu = BCu ^ ((!BCa) & BCe);
    Ebo ^= Do;
    BCa = rol(Ebo, 28);
    Egu ^= Du;
    BCe = rol(Egu, 20);
    Eka ^= Da;
    BCi = rol(Eka, 3);
    Eme ^= De;
    BCo = rol(Eme, 45);
    Esi ^= Di;
    BCu = rol(Esi, 61);
    Aga = BCa ^ ((!BCe) & BCi);
    Age = BCe ^ ((!BCi) & BCo);
    Agi = BCi ^ ((!BCo) & BCu);
    Ago = BCo ^ ((!BCu) & BCa);
    Agu = BCu ^ ((!BCa) & BCe);
    Ebe ^= De;
    BCa = rol(Ebe, 1);
    Egi ^= Di;
    BCe = rol(Egi, 6);
    Eko ^= Do;
    BCi = rol(Eko, 25);
    Emu ^= Du;
    BCo = rol(Emu, 8);
    Esa ^= Da;
    BCu = rol(Esa, 18);
    Aka = BCa ^ ((!BCe) & BCi);
    Ake = BCe ^ ((!BCi) & BCo);
    Aki = BCi ^ ((!BCo) & BCu);
    Ako = BCo ^ ((!BCu) & BCa);
    Aku = BCu ^ ((!BCa) & BCe);
    Ebu ^= Du;
    BCa = rol(Ebu, 27);
    Ega ^= Da;
    BCe = rol(Ega, 36);
    Eke ^= De;
    BCi = rol(Eke, 10);
    Emi ^= Di;
    BCo = rol(Emi, 15);
    Eso ^= Do;
    BCu = rol(Eso, 56);
    Ama = BCa ^ ((!BCe) & BCi);
    Ame = BCe ^ ((!BCi) & BCo);
    Ami = BCi ^ ((!BCo) & BCu);
    Amo = BCo ^ ((!BCu) & BCa);
    Amu = BCu ^ ((!BCa) & BCe);
    Ebi ^= Di;
    BCa = rol(Ebi, 62);
    Ego ^= Do;
    BCe = rol(Ego, 55);
    Eku ^= Du;
    BCi = rol(Eku, 39);
    Ema ^= Da;
    BCo = rol(Ema, 41);
    Ese ^= De;
    BCu = rol(Ese, 2);
    Asa = BCa ^ ((!BCe) & BCi);
    Ase = BCe ^ ((!BCi) & BCo);
    Asi = BCi ^ ((!BCo) & BCu);
    Aso = BCo ^ ((!BCu) & BCa);
    Asu = BCu ^ ((!BCa) & BCe);
    }
    state[0] = Aba;
    state[1] = Abe;
    state[2] = Abi;
    state[3] = Abo;
    state[4] = Abu;
    state[5] = Aga;
    state[6] = Age;
    state[7] = Agi;
    state[8] = Ago;
    state[9] = Agu;
    state[10] = Aka;
    state[11] = Ake;
    state[12] = Aki;
    state[13] = Ako;
    state[14] = Aku;
    state[15] = Ama;
    state[16] = Ame;
    state[17] = Ami;
    state[18] = Amo;
    state[19] = Amu;
    state[20] = Asa;
    state[21] = Ase;
    state[22] = Asi;
    state[23] = Aso;
    state[24] = Asu;
}

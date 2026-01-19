use crate::field::Fr;

pub const CONST_PROOF_SIZE_LOG_N: usize = 28;
pub const NUMBER_OF_SUBRELATIONS: usize = 26;
pub const BATCHED_RELATION_PARTIAL_LENGTH: usize = 8;
pub const NUMBER_OF_ENTITIES: usize = 40;
pub const NUMBER_UNSHIFTED: usize = 35;
pub const NUMBER_TO_BE_SHIFTED: usize = 5;
pub const PAIRING_POINTS_SIZE: usize = 16;
pub const NUMBER_OF_ALPHAS: usize = NUMBER_OF_SUBRELATIONS - 1;

/// Wire indices for the Ultra Honk protocol.
#[derive(Copy, Clone, Debug)]
pub enum Wire {
    Qm = 0,
    Qc = 1,
    Ql = 2,
    Qr = 3,
    Qo = 4,
    Q4 = 5,
    QLookup = 6,
    QArith = 7,
    QRange = 8,
    QElliptic = 9,
    QAux = 10,
    QPoseidon2External = 11,
    QPoseidon2Internal = 12,
    Sigma1 = 13,
    Sigma2 = 14,
    Sigma3 = 15,
    Sigma4 = 16,
    Id1 = 17,
    Id2 = 18,
    Id3 = 19,
    Id4 = 20,
    Table1 = 21,
    Table2 = 22,
    Table3 = 23,
    Table4 = 24,
    LagrangeFirst = 25,
    LagrangeLast = 26,
    Wl = 27,
    Wr = 28,
    Wo = 29,
    W4 = 30,
    ZPerm = 31,
    LookupInverses = 32,
    LookupReadCounts = 33,
    LookupReadTags = 34,
    WlShift = 35,
    WrShift = 36,
    WoShift = 37,
    W4Shift = 38,
    ZPermShift = 39,
}

impl Wire {
    pub fn index(&self) -> usize {
        *self as usize
    }
}

/// A G1 point in affine coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G1Point {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl G1Point {
    pub fn from_xy(x: [u8; 32], y: [u8; 32]) -> Self {
        G1Point { x, y }
    }

    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&bytes[..32]);
        y.copy_from_slice(&bytes[32..]);
        G1Point { x, y }
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.x);
        out[32..].copy_from_slice(&self.y);
        out
    }

    pub fn infinity() -> Self {
        G1Point {
            x: [0u8; 32],
            y: [0u8; 32],
        }
    }

    pub fn generator() -> Self {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x[31] = 1;
        y[31] = 2;
        G1Point { x, y }
    }
}

impl Default for G1Point {
    fn default() -> Self {
        G1Point::infinity()
    }
}

/// The verification key structure
#[derive(Clone, Debug)]
pub struct VerificationKey {
    pub circuit_size: u64,
    pub log_circuit_size: u64,
    pub public_inputs_size: u64,
    // Selectors and wire commitments:
    pub qm: G1Point,
    pub qc: G1Point,
    pub ql: G1Point,
    pub qr: G1Point,
    pub qo: G1Point,
    pub q4: G1Point,
    pub q_lookup: G1Point,
    pub q_arith: G1Point,
    pub q_delta_range: G1Point,
    pub q_elliptic: G1Point,
    pub q_aux: G1Point,
    pub q_poseidon2_external: G1Point,
    pub q_poseidon2_internal: G1Point,
    // Copy constraints:
    pub s1: G1Point,
    pub s2: G1Point,
    pub s3: G1Point,
    pub s4: G1Point,
    pub id1: G1Point,
    pub id2: G1Point,
    pub id3: G1Point,
    pub id4: G1Point,
    // Lookup table commitments:
    pub t1: G1Point,
    pub t2: G1Point,
    pub t3: G1Point,
    pub t4: G1Point,
    // Fixed first/last
    pub lagrange_first: G1Point,
    pub lagrange_last: G1Point,
}

/// The Proof structure
#[derive(Clone, Debug)]
pub struct Proof {
    // Pairing point object (16 Fr elements)
    pub pairing_point_object: [Fr; PAIRING_POINTS_SIZE],
    // Wire commitments
    pub w1: G1Point,
    pub w2: G1Point,
    pub w3: G1Point,
    pub w4: G1Point,
    // Lookup helpers
    pub lookup_read_counts: G1Point,
    pub lookup_read_tags: G1Point,
    pub lookup_inverses: G1Point,
    pub z_perm: G1Point,
    // Sumcheck polynomials
    pub sumcheck_univariates: [[Fr; BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N],
    pub sumcheck_evaluations: [Fr; NUMBER_OF_ENTITIES],
    // Gemini fold commitments
    pub gemini_fold_comms: [G1Point; CONST_PROOF_SIZE_LOG_N - 1],
    pub gemini_a_evaluations: [Fr; CONST_PROOF_SIZE_LOG_N],
    // Shplonk
    pub shplonk_q: G1Point,
    pub kzg_quotient: G1Point,
}

/// Relation parameters (η, η₂, η₃, β, γ, public_inputs_delta).
#[derive(Clone, Debug)]
pub struct RelationParameters {
    pub eta: Fr,
    pub eta_two: Fr,
    pub eta_three: Fr,
    pub beta: Fr,
    pub gamma: Fr,
    pub public_inputs_delta: Fr,
}

/// The transcript holding all Fiat–Shamir challenges.
#[derive(Clone, Debug)]
pub struct Transcript {
    pub rel_params: RelationParameters,
    pub alphas: [Fr; NUMBER_OF_ALPHAS],
    pub gate_challenges: [Fr; CONST_PROOF_SIZE_LOG_N],
    pub sumcheck_u_challenges: [Fr; CONST_PROOF_SIZE_LOG_N],
    pub rho: Fr,
    pub gemini_r: Fr,
    pub shplonk_nu: Fr,
    pub shplonk_z: Fr,
}

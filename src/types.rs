//type.rs
use crate::field::Fr;
use ark_bn254::{Fq, G1Affine};

/// Number of subrelations in the Ultra Honk protocol.
pub const NUMBER_OF_SUBRELATIONS: usize = 26;
pub const CONST_PROOF_SIZE_LOG_N: usize = 28;

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
#[derive(Clone, Debug)]
pub struct G1Point {
    pub x: Fq,
    pub y: Fq,
}

impl G1Point {
    /// Convert an ark_ec-affine point into our wrapper.
    pub fn from_affine(pt: &G1Affine) -> Self {
        G1Point {
            x: pt.x,
            y: pt.y,
        }
    }

    /// Convert back to ark_ec-affine for pairing.
    pub fn to_affine(&self) -> G1Affine {
        G1Affine::new(self.x, self.y)
    }
}

/// The verification key structure, matching TS's VerificationKey interface.
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
    pub q_range: G1Point,
    pub q_aux: G1Point,
    pub q_elliptic: G1Point,
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

/// The Proof structure, matching TS's Proof interface.
#[derive(Clone, Debug)]
pub struct Proof {
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
    pub sumcheck_univariates: Vec<Vec<Fr>>, // 28 × 8
    pub sumcheck_evaluations: Vec<Fr>,      // 40
    // Gemini fold commitments
    pub gemini_fold_comms: Vec<G1Point>,    // 27
    pub gemini_a_evaluations: Vec<Fr>,      // 28
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
    pub alphas: Vec<Fr>,            // 25
    pub gate_challenges: Vec<Fr>,   // logN (28)
    pub sumcheck_u_challenges: Vec<Fr>, // 28
    pub rho: Fr,
    pub gemini_r: Fr,
    pub shplonk_nu: Fr,
    pub shplonk_z: Fr,
}

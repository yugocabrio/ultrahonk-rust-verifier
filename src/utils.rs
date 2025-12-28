//! Utilities for loading Proof and VerificationKey, plus byte↔field/point conversion.

use crate::field::Fr;
use crate::types::{
    G1Point, Proof, VerificationKey, BATCHED_RELATION_PARTIAL_LENGTH, CONST_PROOF_SIZE_LOG_N,
    NUMBER_OF_ENTITIES, PAIRING_POINTS_SIZE,
};
use crate::PROOF_BYTES;
use ark_bn254::{Fq, G1Affine};
use ark_ff::{BigInteger256, PrimeField, Zero};
use core::array;
use num_bigint::BigUint;

/// BigUint -> Fq by LE bytes (auto-reduced mod p)
fn biguint_to_fq_mod(x: &BigUint) -> Fq {
    let le = x.to_bytes_le();
    Fq::from_le_bytes_mod_order(&le)
}

/// Convert 32 bytes into an Fr.
fn bytes_to_fr(bytes: &[u8; 32]) -> Fr {
    Fr::from_bytes(bytes)
}

/// Fq to 32-byte big-endian
pub fn fq_to_be_bytes(f: &Fq) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bi: BigInteger256 = (*f).into(); // 4 × 64-bit limbs (LE)
    for (i, limb) in bi.0.iter().rev().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

/// Fq to (low136, high(<=118)) each 32-byte BE
pub fn fq_to_halves_be(f: &Fq) -> ([u8; 32], [u8; 32]) {
    let be = fq_to_be_bytes(f);
    let big = BigUint::from_bytes_be(&be);
    let mask = (BigUint::from(1u8) << 136) - 1u8; // 2^136 − 1
    let low = &big & &mask; // lower 136 bits
    let high = &big >> 136; // upper bits

    fn to_arr(x: BigUint) -> [u8; 32] {
        let mut arr = [0u8; 32];
        let bytes = x.to_bytes_be();
        arr[32 - bytes.len()..].copy_from_slice(&bytes);
        arr
    }

    (to_arr(low), to_arr(high))
}

/// Load a Proof from a byte array.
///
/// Note (bb v0.87.0): G1 coordinates are encoded as two limbs per coordinate
/// using the (lo136, hi<=118) split and stored in the order (x_lo, x_hi, y_lo, y_hi).
pub fn load_proof(proof_bytes: &[u8]) -> Proof {
    assert_eq!(proof_bytes.len(), PROOF_BYTES, "proof bytes len");
    let mut boundary = 0usize;

    fn read_g1(bytes: &[u8], cur: &mut usize) -> G1Point {
        use num_bigint::BigUint;
        let x0 = BigUint::from_bytes_be(&bytes[*cur..*cur + 32]);
        let x1 = BigUint::from_bytes_be(&bytes[*cur + 32..*cur + 64]);
        let y0 = BigUint::from_bytes_be(&bytes[*cur + 64..*cur + 96]);
        let y1 = BigUint::from_bytes_be(&bytes[*cur + 96..*cur + 128]);
        *cur += 128;
        let shift = 136u32;
        let bx = &x0 | (&x1 << shift);
        let by = &y0 | (&y1 << shift);
        let fx = biguint_to_fq_mod(&bx);
        let fy = biguint_to_fq_mod(&by);
        G1Point { x: fx, y: fy }
    }

    // Helper: read next 32 bytes as Fr
    fn read_fr(bytes: &[u8], cur: &mut usize) -> Fr {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[*cur..*cur + 32]);
        *cur += 32;
        bytes_to_fr(&arr)
    }

    // 0) pairing point object
    let pairing_point_object: [Fr; PAIRING_POINTS_SIZE] =
        array::from_fn(|_| read_fr(proof_bytes, &mut boundary));

    // 1) w1, w2, w3
    let w1 = read_g1(proof_bytes, &mut boundary);
    let w2 = read_g1(proof_bytes, &mut boundary);
    let w3 = read_g1(proof_bytes, &mut boundary);

    // 2) lookup_read_counts, lookup_read_tags
    let lookup_read_counts = read_g1(proof_bytes, &mut boundary);
    let lookup_read_tags = read_g1(proof_bytes, &mut boundary);

    // 3) w4
    let w4 = read_g1(proof_bytes, &mut boundary);

    // 4) lookup_inverses, z_perm
    let lookup_inverses = read_g1(proof_bytes, &mut boundary);
    let z_perm = read_g1(proof_bytes, &mut boundary);

    // 5) sumcheck_univariates
    let mut sumcheck_univariates =
        [[Fr::zero(); BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N];
    for r in 0..CONST_PROOF_SIZE_LOG_N {
        for i in 0..BATCHED_RELATION_PARTIAL_LENGTH {
            sumcheck_univariates[r][i] = read_fr(proof_bytes, &mut boundary);
        }
    }

    // 6) sumcheck_evaluations
    let sumcheck_evaluations: [Fr; NUMBER_OF_ENTITIES] =
        array::from_fn(|_| read_fr(proof_bytes, &mut boundary));

    // 7) gemini_fold_comms
    let gemini_fold_comms: [G1Point; CONST_PROOF_SIZE_LOG_N - 1] =
        array::from_fn(|_| read_g1(proof_bytes, &mut boundary));

    // 8) gemini_a_evaluations
    let gemini_a_evaluations: [Fr; CONST_PROOF_SIZE_LOG_N] =
        array::from_fn(|_| read_fr(proof_bytes, &mut boundary));

    // 9) shplonk_q, kzg_quotient
    let shplonk_q = read_g1(proof_bytes, &mut boundary);
    let kzg_quotient = read_g1(proof_bytes, &mut boundary);

    Proof {
        pairing_point_object,
        w1,
        w2,
        w3,
        w4,
        lookup_read_counts,
        lookup_read_tags,
        lookup_inverses,
        z_perm,
        sumcheck_univariates,
        sumcheck_evaluations,
        gemini_fold_comms,
        gemini_a_evaluations,
        shplonk_q,
        kzg_quotient,
    }
}

/// Load a VerificationKey.
pub fn load_vk_from_bytes(bytes: &[u8]) -> VerificationKey {
    const HEADER_WORDS: usize = 4;
    const NUM_POINTS: usize = 27;
    const EXPECTED_LEN: usize = HEADER_WORDS * 8 + NUM_POINTS * 64;
    assert!(
        bytes.len() == EXPECTED_LEN,
        "vk bytes must be {} bytes (got {})",
        EXPECTED_LEN,
        bytes.len()
    );

    fn read_u64(bytes: &[u8], idx: &mut usize) -> u64 {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes[*idx..*idx + 8]);
        *idx += 8;
        u64::from_be_bytes(arr)
    }
    fn read_point(bytes: &[u8], idx: &mut usize) -> G1Point {
        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&bytes[*idx..*idx + 32]);
        y_bytes.copy_from_slice(&bytes[*idx + 32..*idx + 64]);
        *idx += 64;

        let x = Fq::from_be_bytes_mod_order(&x_bytes);
        let y = Fq::from_be_bytes_mod_order(&y_bytes);

        if x.is_zero() && y.is_zero() {
            return G1Point { x, y };
        }

        let aff = G1Affine::new_unchecked(x, y);
        assert!(aff.is_on_curve(), "vk point not on curve");
        assert!(
            aff.is_in_correct_subgroup_assuming_on_curve(),
            "vk point not in subgroup"
        );
        G1Point { x: aff.x, y: aff.y }
    }

    let mut idx = 0usize;
    let circuit_size = read_u64(bytes, &mut idx);
    let log_circuit_size = read_u64(bytes, &mut idx);
    let public_inputs_size = read_u64(bytes, &mut idx);
    let _pub_inputs_offset = read_u64(bytes, &mut idx);

    let qm = read_point(bytes, &mut idx);
    let qc = read_point(bytes, &mut idx);
    let ql = read_point(bytes, &mut idx);
    let qr = read_point(bytes, &mut idx);
    let qo = read_point(bytes, &mut idx);
    let q4 = read_point(bytes, &mut idx);
    let q_lookup = read_point(bytes, &mut idx);
    let q_arith = read_point(bytes, &mut idx);
    let q_delta_range = read_point(bytes, &mut idx);
    let q_elliptic = read_point(bytes, &mut idx);
    let q_aux = read_point(bytes, &mut idx);
    let q_poseidon2_external = read_point(bytes, &mut idx);
    let q_poseidon2_internal = read_point(bytes, &mut idx);
    let s1 = read_point(bytes, &mut idx);
    let s2 = read_point(bytes, &mut idx);
    let s3 = read_point(bytes, &mut idx);
    let s4 = read_point(bytes, &mut idx);
    let id1 = read_point(bytes, &mut idx);
    let id2 = read_point(bytes, &mut idx);
    let id3 = read_point(bytes, &mut idx);
    let id4 = read_point(bytes, &mut idx);
    let t1 = read_point(bytes, &mut idx);
    let t2 = read_point(bytes, &mut idx);
    let t3 = read_point(bytes, &mut idx);
    let t4 = read_point(bytes, &mut idx);
    let lagrange_first = read_point(bytes, &mut idx);
    let lagrange_last = read_point(bytes, &mut idx);

    VerificationKey {
        circuit_size,
        log_circuit_size,
        public_inputs_size,
        qm,
        qc,
        ql,
        qr,
        qo,
        q4,
        q_lookup,
        q_arith,
        q_delta_range,
        q_elliptic,
        q_aux,
        q_poseidon2_external,
        q_poseidon2_internal,
        s1,
        s2,
        s3,
        s4,
        id1,
        id2,
        id3,
        id4,
        t1,
        t2,
        t3,
        t4,
        lagrange_first,
        lagrange_last,
    }
}

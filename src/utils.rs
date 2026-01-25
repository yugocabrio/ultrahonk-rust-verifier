//! Utilities for loading Proof and VerificationKey, plus byte↔field/point conversion.

use crate::field::Fr;
use crate::types::{
    G1Point, Proof, VerificationKey, BATCHED_RELATION_PARTIAL_LENGTH, CONST_PROOF_SIZE_LOG_N,
    NUMBER_OF_ENTITIES, PAIRING_POINTS_SIZE,
};
use crate::PROOF_BYTES;
use core::array;
use soroban_sdk::Bytes;

/// Convert a 32-byte big-endian array into an Fr.
fn bytes32_to_fr(bytes: &[u8; 32]) -> Fr {
    Fr::from_bytes(bytes)
}

/// Split a 32-byte big-endian field element into (low136, high) limbs.
pub fn coord_to_halves_be(coord: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut low = [0u8; 32];
    let mut high = [0u8; 32];
    low[15..].copy_from_slice(&coord[15..]); // 17 bytes
    high[17..].copy_from_slice(&coord[..15]); // 15 bytes
    (low, high)
}

fn read_bytes<const N: usize>(bytes: &Bytes, idx: &mut u32) -> [u8; N] {
    let mut out = [0u8; N];
    let end = *idx + N as u32;
    bytes.slice(*idx..end).copy_into_slice(&mut out);
    *idx = end;
    out
}

fn combine_limbs(lo: &[u8; 32], hi: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..15].copy_from_slice(&hi[17..]);
    out[15..].copy_from_slice(&lo[15..]);
    out
}

/// Load a Proof from a byte array.
///
/// Note (bb v0.87.0): G1 coordinates are encoded as two limbs per coordinate
/// using the (lo136, hi<=118) split and stored in the order (x_lo, x_hi, y_lo, y_hi).
pub fn load_proof(proof_bytes: &Bytes) -> Proof {
    assert_eq!(proof_bytes.len() as usize, PROOF_BYTES, "proof bytes len");
    let mut boundary = 0u32;

    fn bytes_to_g1_proof_point(bytes: &Bytes, cur: &mut u32) -> G1Point {
        let x0 = read_bytes::<32>(bytes, cur);
        let x1 = read_bytes::<32>(bytes, cur);
        let y0 = read_bytes::<32>(bytes, cur);
        let y1 = read_bytes::<32>(bytes, cur);
        let x = combine_limbs(&x0, &x1);
        let y = combine_limbs(&y0, &y1);
        G1Point { x, y }
    }

    // Helper: bytesToFr (read next 32 bytes as Fr)
    fn bytes_to_fr(bytes: &Bytes, cur: &mut u32) -> Fr {
        let arr = read_bytes::<32>(bytes, cur);
        bytes32_to_fr(&arr)
    }

    // 0) pairing point object
    let pairing_point_object: [Fr; PAIRING_POINTS_SIZE] =
        array::from_fn(|_| bytes_to_fr(proof_bytes, &mut boundary));

    // 1) w1, w2, w3
    let w1 = bytes_to_g1_proof_point(proof_bytes, &mut boundary);
    let w2 = bytes_to_g1_proof_point(proof_bytes, &mut boundary);
    let w3 = bytes_to_g1_proof_point(proof_bytes, &mut boundary);

    // 2) lookup_read_counts, lookup_read_tags
    let lookup_read_counts = bytes_to_g1_proof_point(proof_bytes, &mut boundary);
    let lookup_read_tags = bytes_to_g1_proof_point(proof_bytes, &mut boundary);

    // 3) w4
    let w4 = bytes_to_g1_proof_point(proof_bytes, &mut boundary);

    // 4) lookup_inverses, z_perm
    let lookup_inverses = bytes_to_g1_proof_point(proof_bytes, &mut boundary);
    let z_perm = bytes_to_g1_proof_point(proof_bytes, &mut boundary);

    // 5) sumcheck_univariates
    let mut sumcheck_univariates =
        [[Fr::zero(); BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N];
    for r in 0..CONST_PROOF_SIZE_LOG_N {
        for i in 0..BATCHED_RELATION_PARTIAL_LENGTH {
            sumcheck_univariates[r][i] = bytes_to_fr(proof_bytes, &mut boundary);
        }
    }

    // 6) sumcheck_evaluations
    let sumcheck_evaluations: [Fr; NUMBER_OF_ENTITIES] =
        array::from_fn(|_| bytes_to_fr(proof_bytes, &mut boundary));

    // 7) gemini_fold_comms
    let gemini_fold_comms: [G1Point; CONST_PROOF_SIZE_LOG_N - 1] =
        array::from_fn(|_| bytes_to_g1_proof_point(proof_bytes, &mut boundary));

    // 8) gemini_a_evaluations
    let gemini_a_evaluations: [Fr; CONST_PROOF_SIZE_LOG_N] =
        array::from_fn(|_| bytes_to_fr(proof_bytes, &mut boundary));

    // 9) shplonk_q, kzg_quotient
    let shplonk_q = bytes_to_g1_proof_point(proof_bytes, &mut boundary);
    let kzg_quotient = bytes_to_g1_proof_point(proof_bytes, &mut boundary);

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
pub fn load_vk_from_bytes(bytes: &Bytes) -> Option<VerificationKey> {
    const HEADER_WORDS: usize = 4;
    const NUM_POINTS: usize = 27;
    const EXPECTED_LEN: usize = HEADER_WORDS * 8 + NUM_POINTS * 64;
    if bytes.len() as usize != EXPECTED_LEN {
        return None;
    }

    fn read_u64(bytes: &Bytes, idx: &mut u32) -> u64 {
        u64::from_be_bytes(read_bytes::<8>(bytes, idx))
    }
    fn read_point(bytes: &Bytes, idx: &mut u32) -> Option<G1Point> {
        let x = read_bytes::<32>(bytes, idx);
        let y = read_bytes::<32>(bytes, idx);
        // Curve, subgroup checks are executed in the Soroban host.
        Some(G1Point { x, y })
    }

    let mut idx = 0u32;
    let circuit_size = read_u64(bytes, &mut idx);
    let log_circuit_size = read_u64(bytes, &mut idx);
    let public_inputs_size = read_u64(bytes, &mut idx);
    let _pub_inputs_offset = read_u64(bytes, &mut idx);

    let qm = read_point(bytes, &mut idx)?;
    let qc = read_point(bytes, &mut idx)?;
    let ql = read_point(bytes, &mut idx)?;
    let qr = read_point(bytes, &mut idx)?;
    let qo = read_point(bytes, &mut idx)?;
    let q4 = read_point(bytes, &mut idx)?;
    let q_lookup = read_point(bytes, &mut idx)?;
    let q_arith = read_point(bytes, &mut idx)?;
    let q_delta_range = read_point(bytes, &mut idx)?;
    let q_elliptic = read_point(bytes, &mut idx)?;
    let q_aux = read_point(bytes, &mut idx)?;
    let q_poseidon2_external = read_point(bytes, &mut idx)?;
    let q_poseidon2_internal = read_point(bytes, &mut idx)?;
    let s1 = read_point(bytes, &mut idx)?;
    let s2 = read_point(bytes, &mut idx)?;
    let s3 = read_point(bytes, &mut idx)?;
    let s4 = read_point(bytes, &mut idx)?;
    let id1 = read_point(bytes, &mut idx)?;
    let id2 = read_point(bytes, &mut idx)?;
    let id3 = read_point(bytes, &mut idx)?;
    let id4 = read_point(bytes, &mut idx)?;
    let t1 = read_point(bytes, &mut idx)?;
    let t2 = read_point(bytes, &mut idx)?;
    let t3 = read_point(bytes, &mut idx)?;
    let t4 = read_point(bytes, &mut idx)?;
    let lagrange_first = read_point(bytes, &mut idx)?;
    let lagrange_last = read_point(bytes, &mut idx)?;

    Some(VerificationKey {
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
    })
}

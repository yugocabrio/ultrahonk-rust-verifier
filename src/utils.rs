//! Utilities for loading Proof and VerificationKey, plus byte↔field/point conversion.

use crate::field::Fr;
use crate::types::{G1Point, Proof, VerificationKey};
use ark_bn254::{Fq, G1Affine};
use ark_ff::{BigInteger256, PrimeField};
use num_bigint::BigUint;
use num_traits::Num;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// BigUint -> Fq by LE bytes (auto-reduced mod p)
fn biguint_to_fq_mod(x: &BigUint) -> Fq {
    let le = x.to_bytes_le();
    Fq::from_le_bytes_mod_order(&le)
}

/// Convert 32 bytes into an Fr.
fn bytes_to_fr(bytes: &[u8; 32]) -> Fr {
    Fr::from_bytes(bytes)
}

/// Big-Endian 32 byte to Fq (accept mod p)

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
    let mut cursor = 0usize;

    // Helper: read next 128 bytes as G1Point using 136-bit limb split (x = x0 | (x1<<136))
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

    // 0) pairing point object: 16 Fr elements
    let mut pairing_point_object = Vec::with_capacity(16);
    for _ in 0..16 {
        pairing_point_object.push(read_fr(proof_bytes, &mut cursor));
    }

    // 1) w1, w2, w3
    let w1 = read_g1(proof_bytes, &mut cursor);
    let w2 = read_g1(proof_bytes, &mut cursor);
    let w3 = read_g1(proof_bytes, &mut cursor);

    // 2) lookup_read_counts, lookup_read_tags
    let lookup_read_counts = read_g1(proof_bytes, &mut cursor);
    let lookup_read_tags = read_g1(proof_bytes, &mut cursor);

    // 3) w4
    let w4 = read_g1(proof_bytes, &mut cursor);

    // 4) lookup_inverses, z_perm
    let lookup_inverses = read_g1(proof_bytes, &mut cursor);
    let z_perm = read_g1(proof_bytes, &mut cursor);

    // 5) sumcheck_univariates: 28 rounds × 8 Fr each
    let mut sumcheck_univariates = Vec::new();
    for _ in 0..28 {
        let mut row = Vec::with_capacity(8);
        for _ in 0..8 {
            row.push(read_fr(proof_bytes, &mut cursor));
        }
        sumcheck_univariates.push(row);
    }

    // 6) sumcheck_evaluations
    let mut sumcheck_evaluations = Vec::with_capacity(40);
    for _ in 0..40 {
        sumcheck_evaluations.push(read_fr(proof_bytes, &mut cursor));
    }

    // 7) gemini_fold_comms: 27 G1Points
    let mut gemini_fold_comms = Vec::new();
    for _ in 0..27 {
        gemini_fold_comms.push(read_g1(proof_bytes, &mut cursor));
    }

    // 8) gemini_a_evaluations: 28 Fr
    let mut gemini_a_evaluations = Vec::new();
    for _ in 0..28 {
        gemini_a_evaluations.push(read_fr(proof_bytes, &mut cursor));
    }

    // 9) shplonk_q, kzg_quotient
    let shplonk_q = read_g1(proof_bytes, &mut cursor);
    let kzg_quotient = read_g1(proof_bytes, &mut cursor);

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

/// Load a VerificationKey from a JSON string containing an array of hex‐encoded field‐elements.
#[cfg(feature = "serde_json")]
pub fn load_vk_from_json(json_data: &str) -> VerificationKey {
    let vk_fields: Vec<String> = serde_json::from_str(json_data).unwrap();
    // Header (fields): [circuit_size, public_inputs_size, pub_inputs_offset, reserved]
    const HEADER_WORDS: usize = 4;
    const NUM_POINTS: usize = 27;
    let expected_len = HEADER_WORDS + NUM_POINTS * 4;
    assert!(
        vk_fields.len() >= expected_len,
        "VK JSON must contain at least {} elements (got {})",
        expected_len,
        vk_fields.len()
    );

    fn parse_u64_hex(s: &str) -> u64 {
        let x = BigUint::from_str_radix(s.trim_start_matches("0x"), 16).unwrap();
        x.to_u64_digits().get(0).copied().unwrap_or(0)
    }

    let circuit_size = parse_u64_hex(&vk_fields[0]);
    let public_inputs_size = parse_u64_hex(&vk_fields[1]);
    let pub_inputs_offset = parse_u64_hex(&vk_fields[2]);
    let log_circuit_size = circuit_size.trailing_zeros() as u64;

    // Safe reader: 4 limbs → G1 using fixed v0.87.0 encoding (hi_x, lo_x, hi_y, lo_y) with 136-bit split.
    fn read_g1_from_limbs(hx: &BigUint, lx: &BigUint, hy: &BigUint, ly: &BigUint) -> G1Point {
        let assemble = |hi: &BigUint, lo: &BigUint| -> BigUint { hi | (lo << 136) };
        let x = biguint_to_fq_mod(&assemble(hx, lx));
        let y = biguint_to_fq_mod(&assemble(hy, ly));
        G1Point { x, y }
    }

    let mut field_index = HEADER_WORDS;
    macro_rules! read_g1 {
        () => {{
            let high_x = &vk_fields[field_index];
            let low_x = &vk_fields[field_index + 1];
            let high_y = &vk_fields[field_index + 2];
            let low_y = &vk_fields[field_index + 3];
            let hx = BigUint::from_str_radix(high_x.trim_start_matches("0x"), 16).unwrap();
            let lx = BigUint::from_str_radix(low_x.trim_start_matches("0x"), 16).unwrap();
            let hy = BigUint::from_str_radix(high_y.trim_start_matches("0x"), 16).unwrap();
            let ly = BigUint::from_str_radix(low_y.trim_start_matches("0x"), 16).unwrap();
            field_index += 4;
            read_g1_from_limbs(&hx, &lx, &hy, &ly)
        }};
    }

    // Follow bb v0.87.0 vk_fields.json order (wire/commitment order in fields file):
    // qm, qc, ql, qr, qo, q4, q_lookup, q_arith, q_delta_range, q_elliptic, q_memory(qAux),
    // q_poseidon2_external, q_poseidon2_internal, s1..s4, id1..id4, t1..t4, lagrange_first, lagrange_last
    let qm = read_g1!();
    let qc = read_g1!();
    let ql = read_g1!();
    let qr = read_g1!();
    let qo = read_g1!();
    let q4 = read_g1!();
    let q_lookup = read_g1!();
    let q_arith = read_g1!();
    let q_delta_range = read_g1!();
    let q_elliptic = read_g1!();
    let q_memory = read_g1!(); // qAux
    let q_poseidon2_external = read_g1!();
    let q_poseidon2_internal = read_g1!();
    let s1 = read_g1!();
    let s2 = read_g1!();
    let s3 = read_g1!();
    let s4 = read_g1!();
    // bb v0.87.0 order: IDs come before table commitments
    let id1 = read_g1!();
    let id2 = read_g1!();
    let id3 = read_g1!();
    let id4 = read_g1!();
    let t1 = read_g1!();
    let t2 = read_g1!();
    let t3 = read_g1!();
    let t4 = read_g1!();
    let lagrange_first = read_g1!();
    let lagrange_last = read_g1!();

    VerificationKey {
        circuit_size,
        log_circuit_size,
        public_inputs_size,
        pub_inputs_offset,
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
        q_memory,
        q_nnf: G1Point {
            x: Fq::from(0u64),
            y: Fq::from(0u64),
        },
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

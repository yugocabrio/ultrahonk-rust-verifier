// src/utils.rs
//! Utilities for loading Proof and VerificationKey, plus byte↔field/point conversion.

use crate::field::Fr;
use crate::types::{G1Point, Proof, VerificationKey};
use ark_bn254::Fq;
use ark_ff::{BigInteger256, PrimeField};
use num_bigint::BigUint;
use num_traits::Num;

#[cfg(feature = "std")]
use std::fs::File;
#[cfg(feature = "std")]
use std::io::Read;

#[cfg(not(feature = "std"))]
use alloc::{vec::Vec, string::String};

/// Convert 32 bytes into an Fr.
fn bytes_to_fr(bytes: &[u8; 32]) -> Fr {
    Fr::from_bytes(bytes)
}

/// Big-Endian 32 byte → Fq (accept mod p)
fn fq_from_be_bytes(bytes_be: &[u8; 32]) -> Fq {
    let mut bytes_le = *bytes_be; // 32-byte copy
    bytes_le.reverse(); // BE → LE
    Fq::from_le_bytes_mod_order(&bytes_le)
}

/// Fq → 32-byte big-endian
pub fn fq_to_be_bytes(f: &Fq) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bi: BigInteger256 = (*f).into(); // 4 × 64-bit limbs (LE)
    for (i, limb) in bi.0.iter().rev().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

/// Fq → (low136, high120) each 32-byte BE
pub fn fq_to_halves_be(f: &Fq) -> ([u8; 32], [u8; 32]) {
    let be = fq_to_be_bytes(f);
    let big = BigUint::from_bytes_be(&be);
    let mask = (BigUint::from(1u8) << 136) - 1u8; // 2¹³⁶ − 1
    let low = &big & &mask; // lower 136 bits
    let high = &big >> 136; // upper 120 bits

    // biguint → 32-byte BE
    fn to_arr(x: BigUint) -> [u8; 32] {
        let mut arr = [0u8; 32];
        let bytes = x.to_bytes_be();
        arr[32 - bytes.len()..].copy_from_slice(&bytes);
        arr
    }

    (to_arr(low), to_arr(high))
}

/// Convert 128 bytes into a G1Point.
/// The layout is four consecutive 32‐byte chunks: x_low, x_high, y_low, y_high.
/// We reconstruct a 256-bit coordinate by shifting high<<136 + low.
fn bytes_to_g1_point(bytes: &[u8]) -> G1Point {
    assert_eq!(bytes.len(), 128);
    // Parse low/high for x:
    let x_low = BigUint::from_bytes_be(&bytes[0..32]);
    let x_high = BigUint::from_bytes_be(&bytes[32..64]);
    // Parse low/high for y:
    let y_low = BigUint::from_bytes_be(&bytes[64..96]);
    let y_high = BigUint::from_bytes_be(&bytes[96..128]);

    // Combine: high << 136 bits, plus low.
    let shift_bits = 136u32;
    let big_x = (x_high << shift_bits) | x_low;
    let big_y = (y_high << shift_bits) | y_low;

    // Convert BigUint -> 32 bytes → Fq
    let x_bytes = big_x.to_bytes_be();
    let mut x_arr = [0u8; 32];
    x_arr[32 - x_bytes.len()..].copy_from_slice(&x_bytes);
    let fq_x = fq_from_be_bytes(&x_arr);

    let y_bytes = big_y.to_bytes_be();
    let mut y_arr = [0u8; 32];
    y_arr[32 - y_bytes.len()..].copy_from_slice(&y_bytes);
    let fq_y = fq_from_be_bytes(&y_arr);

    G1Point { x: fq_x, y: fq_y }
}

/// Load a Proof from a byte array (e.g. read from proof.bin).
pub fn load_proof(proof_bytes: &[u8]) -> Proof {
    let mut cursor = 0usize;

    // Helper: read next 128 bytes as G1Point
    fn read_g1(bytes: &[u8], cur: &mut usize) -> G1Point {
        let pt = bytes_to_g1_point(&bytes[*cur..*cur + 128]);
        *cur += 128;
        pt
    }

    // Helper: read next 32 bytes as Fr
    fn read_fr(bytes: &[u8], cur: &mut usize) -> Fr {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[*cur..*cur + 32]);
        *cur += 32;
        bytes_to_fr(&arr)
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

    // 6) sumcheck_evaluations: 40 Fr
    let mut sumcheck_evaluations = Vec::new();
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

/// Combine two consecutive 256-bit field elements (each represented as hex string) into a single BigUint.
fn combine_fields(low_str: &str, high_str: &str) -> BigUint {
    // Both strings start with "0x", so strip that.
    let low_hex = low_str.trim_start_matches("0x");
    let high_hex = high_str.trim_start_matches("0x");

    // Parse low/high into BigUint
    let low = BigUint::from_str_radix(low_hex, 16).unwrap();
    let high = BigUint::from_str_radix(high_hex, 16).unwrap();

    // high << (34*4) bits = high << 136

    (high << 136) | low
}

/// Load a VerificationKey from a JSON file containing an array of hex‐encoded field‐elements.
#[cfg(feature = "std")]
pub fn load_vk(path: &str) -> VerificationKey {
    // Read entire file as string
    let mut file = File::open(path).expect("VK JSON file not found");
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();

    // Parse JSON into Vec<String>
    let vk_fields: Vec<String> = serde_json::from_str(&data).unwrap();
    // Ensure we have at least the minimal length
    assert!(
        vk_fields.len() > 127,
        "VK JSON must contain at least 128 field elements"
    );

    // Parse circuit params:
    let circuit_size = BigUint::from_str_radix(vk_fields[0].trim_start_matches("0x"), 16)
        .unwrap()
        .to_u64_digits(); // But we know it's u64
    let circuit_size_u64 = circuit_size[0];
    let public_inputs_size = BigUint::from_str_radix(vk_fields[1].trim_start_matches("0x"), 16)
        .unwrap()
        .to_u64_digits()[0];
    let log_circuit_size = (circuit_size_u64 as f64).log2() as u64;

    // Helper to convert combined BigUint into an Fq
    fn biguint_to_fq(x: BigUint) -> Fq {
        let be = x.to_bytes_be();
        let mut arr = [0u8; 32];
        arr[32 - be.len()..].copy_from_slice(&be);
        fq_from_be_bytes(&arr)
    }

    // Starting index for G1 points: 20
    let mut field_index = 20;

    macro_rules! read_g1 {
        () => {{
            // Each G1Point uses 4 consecutive fields: low_x, high_x, low_y, high_y
            let low_x = &vk_fields[field_index];
            let high_x = &vk_fields[field_index + 1];
            let low_y = &vk_fields[field_index + 2];
            let high_y = &vk_fields[field_index + 3];
            let big_x = combine_fields(low_x, high_x);
            let big_y = combine_fields(low_y, high_y);
            field_index += 4;
            G1Point {
                x: biguint_to_fq(big_x),
                y: biguint_to_fq(big_y),
            }
        }};
    }

    let qm = read_g1!();
    let qc = read_g1!();
    let ql = read_g1!();
    let qr = read_g1!();
    let qo = read_g1!();
    let q4 = read_g1!();
    let q_lookup = read_g1!();
    let q_arith = read_g1!();
    let q_range = read_g1!();
    let q_aux = read_g1!();
    let q_elliptic = read_g1!();
    let q_poseidon2_external = read_g1!();
    let q_poseidon2_internal = read_g1!();
    let s1 = read_g1!();
    let s2 = read_g1!();
    let s3 = read_g1!();
    let s4 = read_g1!();
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
        circuit_size: circuit_size_u64,
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
        q_range,
        q_aux,
        q_elliptic,
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

/// Load a proof and public inputs from a byte array.
pub fn load_proof_and_public_inputs(bytes: &[u8]) -> (Vec<Fr>, Vec<u8>) {
    // First 4 bytes = total number of field elements (big-endian)
    let total_fields = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;

    // Proof is always 440 field elements
    const PROOF_NUM_FIELDS: usize = 440;
    assert!(
        total_fields >= PROOF_NUM_FIELDS,
        "total_fields < proof field count"
    );
    let num_inputs = total_fields - PROOF_NUM_FIELDS;

    // Next num_inputs × 32 bytes = public inputs
    let mut public_inputs = Vec::with_capacity(num_inputs);
    let mut cursor = 4; // start right after the 4-byte header
    for _ in 0..num_inputs {
        let mut bytes32 = [0u8; 32];
        bytes32.copy_from_slice(&bytes[cursor..cursor + 32]);
        public_inputs.push(bytes_to_fr(&bytes32));
        cursor += 32;
    }

    // Remaining bytes = proof (must be 440 × 32 bytes)
    let proof_bytes = bytes[cursor..].to_vec();
    assert!(
        proof_bytes.len() == PROOF_NUM_FIELDS * 32,
        "invalid proof length"
    );

    (public_inputs, proof_bytes)
}

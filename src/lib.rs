#![no_std]
extern crate alloc;

use alloc::{string::String as StdString, vec::Vec as StdVec};
use core::str;

use soroban_sdk::{contract, contracterror, contractimpl, Bytes, BytesN, Env};
use soroban_sdk::crypto::Hash;

use ark_bn254::Fq;
use ark_ff::PrimeField; // trait required so that from_be_bytes_mod_order is available. :contentReference[oaicite:0]{index=0}

use num_bigint::BigUint;
use num_traits::Zero;

use ultrahonk_rust_verifier::{
    UltraHonkVerifier,
    utils::load_proof_and_public_inputs,
    types::{VerificationKey, G1Point},
};

/// Helper: big-endian 32-byte → Fq
fn fq_from_be_bytes(bytes_be: &[u8; 32]) -> Fq {
    // Requires PrimeField in scope so that provided method exists. :contentReference[oaicite:1]{index=1}
    Fq::from_be_bytes_mod_order(bytes_be)
}

/// Combine low/high hex field elements into a single BigUint: (high << 136) | low
fn combine_fields(low_str: &str, high_str: &str) -> BigUint {
    let low = BigUint::parse_bytes(low_str.trim_start_matches("0x").as_bytes(), 16)
        .expect("invalid hex in low part");
    let high = BigUint::parse_bytes(high_str.trim_start_matches("0x").as_bytes(), 16)
        .expect("invalid hex in high part");
    (high << 136) | low
}

/// Parse a JSON array of strings like `["0xabc", "0xdef", ...]` without using serde_json.
fn parse_json_array_of_strings(s: &str) -> Result<StdVec<StdString>, ()> {
    let mut out: StdVec<StdString> = StdVec::new();
    let mut chars = s.chars().peekable();

    // Skip whitespace
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else {
            break;
        }
    }

    // Expect opening '['
    if chars.next() != Some('[') {
        return Err(());
    }

    loop {
        // Skip whitespace and commas
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() || c == ',' {
                chars.next();
            } else {
                break;
            }
        }

        // End?
        if let Some(&']') = chars.peek() {
            chars.next();
            break;
        }

        // Expect opening quote
        if chars.next() != Some('"') {
            return Err(());
        }

        // Collect string
        let mut buf = StdString::new();
        while let Some(c) = chars.next() {
            if c == '"' {
                break;
            }
            if c == '\\' {
                // simple escape handling
                if let Some(next) = chars.next() {
                    buf.push(next);
                }
            } else {
                buf.push(c);
            }
        }
        out.push(buf);
    }

    Ok(out)
}

/// Load a verification key from a JSON string of hex field elements WITHOUT serde_json.
fn load_vk_from_json_no_serde(json_data: &str) -> Result<VerificationKey, ()> {
    let vk_fields = parse_json_array_of_strings(json_data)?;
    if vk_fields.len() <= 127 {
        return Err(());
    }

    // Parse circuit params
    let circuit_size_big: BigUint = BigUint::parse_bytes(
        vk_fields[0].trim_start_matches("0x").as_bytes(),
        16,
    )
    .ok_or(())?;
    let circuit_size_u64_vec = circuit_size_big.to_u64_digits();
    let circuit_size_u64 = *circuit_size_u64_vec
        .get(0)
        .ok_or(())?;

    let public_inputs_size_big: BigUint = BigUint::parse_bytes(
        vk_fields[1].trim_start_matches("0x").as_bytes(),
        16,
    )
    .ok_or(())?;
    let public_inputs_size = *public_inputs_size_big.to_u64_digits().get(0).ok_or(())?;

    // Compute log_circuit_size
    let mut n = circuit_size_u64;
    let mut log = 0;
    while n > 1 {
        n >>= 1;
        log += 1;
    }

    // Helper to convert BigUint → Fq
    fn biguint_to_fq(x: BigUint) -> Fq {
        let be = x.to_bytes_be();
        let mut arr = [0u8; 32];
        arr[32 - be.len()..].copy_from_slice(&be);
        fq_from_be_bytes(&arr)
    }

    // Starting index for G1 points: 20
    let mut field_index = 20usize;

    macro_rules! read_g1 {
        () => {{
            let low_x = &vk_fields[field_index];
            let high_x = &vk_fields[field_index + 1];
            let low_y = &vk_fields[field_index + 2];
            let high_y = &vk_fields[field_index + 3];
            field_index += 4;
            G1Point {
                x: biguint_to_fq(combine_fields(low_x, high_x)),
                y: biguint_to_fq(combine_fields(low_y, high_y)),
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

    Ok(VerificationKey {
        circuit_size: circuit_size_u64,
        log_circuit_size: log,
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
    })
}

/// Contract name
#[contract]
pub struct UltraHonkVerifierContract;

/// Custom errors for contract operations.
#[contracterror]
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    VkParseError = 1,
    ProofParseError = 2,
    VerificationFailed = 3,
}

#[contractimpl]
impl UltraHonkVerifierContract {
    /// Verifies an UltraHonk proof and stores the proof_id (keccak256 of the blob) on success.
    pub fn verify_proof(
        env: Env,
        vk_json: Bytes,
        proof_blob: Bytes,
    ) -> Result<BytesN<32>, Error> {
        // Compute proof_id = keccak256(proof_blob)
        let proof_id_hash: Hash<32> = env.crypto().keccak256(&proof_blob);
        let proof_id_bytes: BytesN<32> = proof_id_hash.to_bytes();

        // Parse vk_json to &str
        let vk_vec: StdVec<u8> = vk_json.to_alloc_vec(); // requires soroban-sdk alloc feature. :contentReference[oaicite:2]{index=2}
        let vk_str = str::from_utf8(&vk_vec).map_err(|_| Error::VkParseError).unwrap_or_default();

        // Build verification key manually (no serde_json)
        let vk = load_vk_from_json_no_serde(vk_str).map_err(|_| Error::VkParseError)?;

        // Create verifier with the parsed VK
        let verifier = UltraHonkVerifier::new_with_vk(vk);

        // Parse proof_blob into public inputs + proof bytes
        let proof_vec: StdVec<u8> = proof_blob.to_alloc_vec();
        let (pub_inputs, proof_bytes) =
            load_proof_and_public_inputs(&proof_vec); // if this panics upstream, consider wrapping for safety

        // Convert public inputs into expected form: Vec<Vec<u8>>
        let pub_inputs_bytes: StdVec<StdVec<u8>> =
            pub_inputs.iter().map(|fr| fr.to_bytes().to_vec()).collect();

        // Run verification
        verifier
            .verify(&proof_bytes, &pub_inputs_bytes)
            .map_err(|_| Error::VerificationFailed)?;

        // Persist success
        env.storage().instance().set(&proof_id_bytes, &true);

        Ok(proof_id_bytes)
    }

    /// Checks if a given proof_id (keccak256 of proof blob) was previously verified.
    pub fn is_verified(env: Env, proof_id: BytesN<32>) -> bool {
        env.storage().instance().get(&proof_id).unwrap_or(false)
    }
}

#![no_std]
extern crate alloc;

use alloc::{string::String as StdString, vec::Vec as StdVec};
use core::str;

use soroban_sdk::{contract, contracterror, contractimpl, Bytes, BytesN, Env};
use sha3::{Digest, Keccak256};

use ark_bn254::{Fq, G1Affine};
use ark_ff::PrimeField;

use num_bigint::BigUint;

use ultrahonk_rust_verifier::{
    types::{G1Point, VerificationKey},
    UltraHonkVerifier,
};

/// 32-byte big-endian → Fq
#[inline(always)]
fn fq_from_be_bytes(bytes_be: &[u8; 32]) -> Fq {
    Fq::from_be_bytes_mod_order(bytes_be)
}

/// BigUint → Fq (auto-reduced mod p)
#[inline(always)]
fn biguint_to_fq(x: &BigUint) -> Fq {
    let be = x.to_bytes_be();
    let mut arr = [0u8; 32];
    if be.len() >= 32 {
        // take the least-significant 32 bytes
        arr.copy_from_slice(&be[be.len() - 32..]);
    } else {
        arr[32 - be.len()..].copy_from_slice(&be);
    }
    fq_from_be_bytes(&arr)
}

/// Parse `["0x..","0x..", ...]` (no serde)
fn parse_json_array_of_strings(s: &str) -> Result<StdVec<StdString>, ()> {
    let mut out: StdVec<StdString> = StdVec::new();
    let mut chars = s.chars().peekable();

    // skip ws
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else {
            break;
        }
    }
    if chars.next() != Some('[') {
        return Err(());
    }

    loop {
        // skip ws/commas
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() || c == ',' {
                chars.next();
            } else {
                break;
            }
        }
        if let Some(&']') = chars.peek() {
            chars.next();
            break;
        }
        if chars.next() != Some('"') {
            return Err(());
        }
        let mut buf = StdString::new();
        while let Some(c) = chars.next() {
            if c == '"' {
                break;
            }
            if c == '\\' {
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

/// Robust point assembly matching the library semantics:
/// - try shift=136, then shift=128
/// - for each shift, try (x=lx|hx<<s, y=ly|hy<<s) and XY-swapped
fn read_g1_from_limbs(lx: &BigUint, hx: &BigUint, ly: &BigUint, hy: &BigUint) -> Option<G1Point> {
    let assemble = |lo: &BigUint, hi: &BigUint, shift: u32| -> BigUint { lo | (hi << shift) };
    let shifts = [136u32, 128u32];

    for &shift in &shifts {
        // normal order
        let bx = assemble(lx, hx, shift);
        let by = assemble(ly, hy, shift);
        let px = biguint_to_fq(&bx);
        let py = biguint_to_fq(&by);
        let aff = G1Affine::new_unchecked(px, py);
        if aff.is_on_curve() && aff.is_in_correct_subgroup_assuming_on_curve() {
            return Some(G1Point { x: aff.x, y: aff.y });
        }

        // XY swap
        let bx = assemble(ly, hy, shift);
        let by = assemble(lx, hx, shift);
        let px = biguint_to_fq(&bx);
        let py = biguint_to_fq(&by);
        let aff = G1Affine::new_unchecked(px, py);
        if aff.is_on_curve() && aff.is_in_correct_subgroup_assuming_on_curve() {
            return Some(G1Point { x: aff.x, y: aff.y });
        }
    }
    None
}

/// Try read a single G1 from 4 limbs at index i
fn try_read_g1(vk_fields: &[StdString], i: usize) -> Option<(G1Point, usize)> {
    if i + 3 >= vk_fields.len() {
        return None;
    }
    let parse = |s: &str| BigUint::parse_bytes(s.trim_start_matches("0x").as_bytes(), 16);
    let lx = parse(&vk_fields[i])?;
    let hx = parse(&vk_fields[i + 1])?;
    let ly = parse(&vk_fields[i + 2])?;
    let hy = parse(&vk_fields[i + 3])?;

    let pt = read_g1_from_limbs(&lx, &hx, &ly, &hy)?;
    Some((pt, i + 4))
}

/// Lookahead to find the first index where 27 consecutive points decode on-curve.
/// This avoids false sync on a single accidental on-curve tuple.
fn find_first_g1_start(
    vk_fields: &[StdString],
    start_guess: usize,
    max_probe: usize,
) -> Option<usize> {
    const TOTAL_POINTS: usize = 27;
    const TOTAL_LIMBS: usize = TOTAL_POINTS * 4;

    let end = core::cmp::min(vk_fields.len(), start_guess + max_probe);
    'probe: for i in start_guess..end {
        if i + TOTAL_LIMBS > vk_fields.len() {
            break;
        }
        let mut idx = i;
        for _ in 0..TOTAL_POINTS {
            if let Some((_pt, next)) = try_read_g1(vk_fields, idx) {
                idx = next;
            } else {
                continue 'probe;
            }
        }
        return Some(i);
    }
    None
}

/// Manual loader for `vk_fields.json` (bb v0.87.0 layout) without serde.
/// Replicates the ordering used in the library's parser and enforces robust sync.
fn load_vk_from_json_no_serde(json_data: &str) -> Result<VerificationKey, ()> {
    let vk_fields = parse_json_array_of_strings(json_data)?;
    if vk_fields.len() < 3 + 4 {
        return Err(());
    }

    // Header: [0]=logN or circuit_size, [1]=num_public_inputs, [2]=pub_inputs_offset
    let parse_u64 = |s: &str| -> u64 {
        BigUint::parse_bytes(s.trim_start_matches("0x").as_bytes(), 16)
            .and_then(|b| b.to_u64_digits().get(0).copied())
            .unwrap_or(0)
    };

    let h0 = parse_u64(&vk_fields[0]);
    let public_inputs_size = if vk_fields.len() > 1 {
        parse_u64(&vk_fields[1])
    } else {
        0
    };
    let pub_inputs_offset = if vk_fields.len() > 2 {
        parse_u64(&vk_fields[2])
    } else {
        0
    };

    // Interpret h0: power-of-two => circuit_size; else => logN
    let (circuit_size, log_circuit_size) = if h0 != 0 && (h0 & (h0 - 1)) == 0 {
        // h0 is circuit_size
        let mut lg = 0u64;
        let mut n = h0;
        while n > 1 {
            n >>= 1;
            lg += 1;
        }
        (h0, lg)
    } else {
        // h0 is logN
        let cs = 1u64.checked_shl(h0 as u32).ok_or(())?;
        (cs, h0)
    };

    // Start of G1 limbs: find index where 27 consecutive points decode properly.
    let mut idx = find_first_g1_start(&vk_fields, 3, 64).ok_or(())?;

    macro_rules! read_g1 {
        () => {{
            let (pt, next) = try_read_g1(&vk_fields, idx).ok_or(())?;
            idx = next;
            pt
        }};
    }

    // Follow bb v0.87.0 vk_fields order:
    // qm, qc, ql, qr, qo, q4, q_lookup, q_arith, q_delta_range, q_elliptic, q_memory (qAux),
    // q_poseidon2_external, q_poseidon2_internal,
    // s1..s4,
    // id1..id4,
    // t1..t4,
    // lagrange_first, lagrange_last
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
    })
}

/// Contract
#[contract]
pub struct UltraHonkVerifierContract;

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
    /// Split a packed [4-byte count][public_inputs][proof] buffer into
    /// (public_inputs as 32-byte big-endian slices, proof bytes).
    /// Accepts proof sections of either 440 or 456 field elements (BN254), to be
    /// compatible with differing bb versions.
    fn split_inputs_and_proof_bytes(packed: &[u8]) -> (StdVec<StdVec<u8>>, StdVec<u8>) {
        if packed.len() < 4 {
            return (StdVec::new(), packed.to_vec());
        }
        let rest = &packed[4..];
        for &pf in &[456usize, 440usize] {
            let need = pf * 32;
            if rest.len() >= need {
                let pis_len = rest.len() - need;
                if pis_len % 32 == 0 {
                    let mut pub_inputs_bytes: StdVec<StdVec<u8>> =
                        StdVec::with_capacity(pis_len / 32);
                    for chunk in rest[..pis_len].chunks(32) {
                        pub_inputs_bytes.push(chunk.to_vec());
                    }
                    let proof_bytes = rest[pis_len..].to_vec();
                    return (pub_inputs_bytes, proof_bytes);
                }
            }
        }
        (StdVec::new(), rest.to_vec())
    }
    /// Verify an UltraHonk proof; on success store proof_id (= keccak256(proof_blob))
    pub fn verify_proof(env: Env, vk_json: Bytes, proof_blob: Bytes) -> Result<BytesN<32>, Error> {
        // proof_id = keccak256(proof_blob) computed locally to avoid host VM limits
        let proof_vec: StdVec<u8> = proof_blob.to_alloc_vec();
        let mut hasher = Keccak256::new();
        hasher.update(&proof_vec);
        let digest = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&digest);
        let proof_id_bytes: BytesN<32> = BytesN::from_array(&env, &arr);

        // vk_json → &str  (avoid temporary drop by binding first)
        let vk_vec: StdVec<u8> = vk_json.to_alloc_vec();
        let vk_str = str::from_utf8(&vk_vec).map_err(|_| Error::VkParseError)?;

        // Build VK (manual JSON parser; no serde_json needed)
        let vk = load_vk_from_json_no_serde(vk_str).map_err(|_| Error::VkParseError)?;

        // Verifier (moves vk)
        let verifier = UltraHonkVerifier::new_with_vk(vk);

        // Proof & public inputs (tolerate 440 or 456 field proofs)
        let (pub_inputs_bytes, proof_bytes) =
            Self::split_inputs_and_proof_bytes(&proof_vec);

        // Verify
        verifier
            .verify(&proof_bytes, &pub_inputs_bytes)
            .map_err(|_| Error::VerificationFailed)?;

        // Persist success
        env.storage().instance().set(&proof_id_bytes, &true);

        Ok(proof_id_bytes)
    }

    /// Query if a proof_id was previously verified
    pub fn is_verified(env: Env, proof_id: BytesN<32>) -> bool {
        env.storage().instance().get(&proof_id).unwrap_or(false)
    }
}

#![no_std]
extern crate alloc;

use alloc::{boxed::Box, string::String as StdString, vec::Vec as StdVec};
use core::str;

use soroban_sdk::{
    contract, contracterror, contractimpl, symbol_short,
    crypto::bn254::{Fr as HostFr, G1Affine as HostG1Affine, G2Affine as HostG2Affine},
    Bytes, BytesN, Env, Symbol, Vec as SorobanVec,
};

use ark_bn254::{Fq, Fq2, G1Affine as ArkG1Affine, G2Affine as ArkG2Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_ff::PrimeField;

use ultrahonk_rust_verifier::{
    ec::{self, Bn254Ops},
    field::Fr as ArkFr,
    hash::{self, HashOps},
    types::{G1Point, VerificationKey},
    UltraHonkVerifier,
};

/// 32-byte big-endian → Fq
#[inline(always)]
fn fq_from_be_bytes(bytes_be: &[u8; 32]) -> Fq {
    Fq::from_be_bytes_mod_order(bytes_be)
}

/// Fq → 32-byte big-endian
#[inline(always)]
fn fq_to_be_bytes(value: &Fq) -> [u8; 32] {
    use ark_ff::BigInteger;

    let mut out = [0u8; 32];
    let bytes = (*value).into_bigint().to_bytes_be();
    let offset = 32 - bytes.len();
    out[offset..].copy_from_slice(&bytes);
    out
}

#[inline(always)]
fn rhs_g2_affine() -> ArkG2Affine {
    let x = Fq2::new(
        Fq::from_le_bytes_mod_order(&[
            0xed, 0xf6, 0x92, 0xd9, 0x5c, 0xbd, 0xde, 0x46, 0xdd, 0xda, 0x5e, 0xf7, 0xd4, 0x22,
            0x43, 0x67, 0x79, 0x44, 0x5c, 0x5e, 0x66, 0x00, 0x6a, 0x42, 0x76, 0x1e, 0x1f, 0x12,
            0xef, 0xde, 0x00, 0x18,
        ]),
        Fq::from_le_bytes_mod_order(&[
            0xc2, 0x12, 0xf3, 0xae, 0xb7, 0x85, 0xe4, 0x97, 0x12, 0xe7, 0xa9, 0x35, 0x33, 0x49,
            0xaa, 0xf1, 0x25, 0x5d, 0xfb, 0x31, 0xb7, 0xbf, 0x60, 0x72, 0x3a, 0x48, 0x0d, 0x92,
            0x93, 0x93, 0x8e, 0x19,
        ]),
    );
    let y = Fq2::new(
        Fq::from_le_bytes_mod_order(&[
            0xaa, 0x7d, 0xfa, 0x66, 0x01, 0xcc, 0xe6, 0x4c, 0x7b, 0xd3, 0x43, 0x0c, 0x69, 0xe7,
            0xd1, 0xe3, 0x8f, 0x40, 0xcb, 0x8d, 0x80, 0x71, 0xab, 0x4a, 0xeb, 0x6d, 0x8c, 0xdb,
            0xa5, 0x5e, 0xc8, 0x12,
        ]),
        Fq::from_le_bytes_mod_order(&[
            0x5b, 0x97, 0x22, 0xd1, 0xdc, 0xda, 0xac, 0x55, 0xf3, 0x8e, 0xb3, 0x70, 0x33, 0x31,
            0x4b, 0xbc, 0x95, 0x33, 0x0c, 0x69, 0xad, 0x99, 0x9e, 0xec, 0x75, 0xf0, 0x5f, 0x58,
            0xd0, 0x89, 0x06, 0x09,
        ]),
    );
    ArkG2Affine::new_unchecked(x, y)
}

#[inline(always)]
fn lhs_g2_affine() -> ArkG2Affine {
    let x = Fq2::new(
        Fq::from_le_bytes_mod_order(&[
            0xb0, 0x83, 0x88, 0x93, 0xec, 0x1f, 0x23, 0x7e, 0x8b, 0x07, 0x32, 0x3b, 0x07, 0x44,
            0x59, 0x9f, 0x4e, 0x97, 0xb5, 0x98, 0xb3, 0xb5, 0x89, 0xbc, 0xc2, 0xbc, 0x37, 0xb8,
            0xd5, 0xc4, 0x18, 0x01,
        ]),
        Fq::from_le_bytes_mod_order(&[
            0xc1, 0x83, 0x93, 0xc0, 0xfa, 0x30, 0xfe, 0x4e, 0x8b, 0x03, 0x8e, 0x35, 0x7a, 0xd8,
            0x51, 0xea, 0xe8, 0xde, 0x91, 0x07, 0x58, 0x4e, 0xff, 0xe7, 0xc7, 0xf1, 0xf6, 0x51,
            0xb2, 0x01, 0x0e, 0x26,
        ]),
    );
    let y = Fq2::new(
        Fq::from_le_bytes_mod_order(&[
            0x55, 0x5e, 0xcc, 0xda, 0xd4, 0x87, 0x4a, 0x85, 0xa2, 0xce, 0xe6, 0x96, 0x3f, 0xdd,
            0xe6, 0x11, 0x5e, 0x61, 0xe5, 0x14, 0x42, 0x5b, 0x47, 0x56, 0x2a, 0x63, 0xc0, 0xc0,
            0xa3, 0xbd, 0xfe, 0x22,
        ]),
        Fq::from_le_bytes_mod_order(&[
            0xe4, 0x5f, 0x6a, 0xda, 0x80, 0x3c, 0x41, 0xee, 0xa4, 0x9b, 0xf9, 0x41, 0x46, 0xa0,
            0xf2, 0x9c, 0x85, 0x72, 0x9a, 0xbb, 0xc1, 0x56, 0x51, 0xd2, 0xe3, 0x0f, 0x11, 0xf7,
            0x69, 0x63, 0xfc, 0x04,
        ]),
    );
    ArkG2Affine::new_unchecked(x, y)
}

fn ark_g1_affine_to_bytes(pt: &ArkG1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    pt.serialize_uncompressed(&mut out[..])
        .expect("G1 serialize");
    out
}

fn ark_g2_affine_to_bytes(pt: &ArkG2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    pt.serialize_uncompressed(&mut out[..])
        .expect("G2 serialize");
    out
}

fn host_g1_to_ark(pt: &HostG1Affine) -> Result<ArkG1Affine, StdString> {
    let mut bytes = [0u8; 64];
    pt.to_bytes().copy_into_slice(&mut bytes);
    ArkG1Affine::deserialize_uncompressed(&bytes[..])
        .map_err(|_| "host returned invalid G1 point".into())
}

fn ark_g1_to_host(env: &Env, pt: &ArkG1Affine) -> HostG1Affine {
    let bytes = ark_g1_affine_to_bytes(pt);
    HostG1Affine::from_bytes(BytesN::from_array(env, &bytes))
}

fn ark_g2_to_host(env: &Env, pt: &ArkG2Affine) -> HostG2Affine {
    let bytes = ark_g2_affine_to_bytes(pt);
    HostG2Affine::from_bytes(BytesN::from_array(env, &bytes))
}

fn g1_point_to_host(env: &Env, pt: &G1Point) -> HostG1Affine {
    let aff = pt.to_affine();
    ark_g1_to_host(env, &aff)
}

fn ark_fr_to_host(env: &Env, scalar: &ArkFr) -> HostFr {
    HostFr::from_bytes(BytesN::from_array(env, &scalar.to_bytes()))
}

/// Parse a hex string (optional 0x prefix) into a 32-byte big-endian array.
/// Takes the least-significant 32 bytes if longer.
#[inline(never)]
fn hex_str_to_be32(s: &str) -> Option<[u8; 32]> {
    #[inline(always)]
    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(10 + (b - b'a')),
            b'A'..=b'F' => Some(10 + (b - b'A')),
            _ => None,
        }
    }
    let hex = s.trim_start_matches("0x").as_bytes();
    let mut out = [0u8; 32];
    let mut oi = 32usize;
    let mut i = hex.len();
    // pack from least-significant end
    while i > 0 && oi > 0 {
        // low nibble
        let low = hex_val(hex[i - 1])?;
        i -= 1;
        // high nibble (may be absent)
        let high = if i > 0 {
            let v = hex_val(hex[i - 1])?;
            i -= 1;
            v
        } else {
            0
        };
        oi -= 1;
        out[oi] = (high << 4) | low;
    }
    Some(out)
}

/// Combine lo | (hi << shift_bytes) where shift is 16 or 17 bytes; return the least-significant 32 bytes.
#[inline(never)]
fn or_with_left_shift_bytes(lo: &[u8; 32], hi: &[u8; 32], shift_bytes: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    if shift_bytes >= 32 {
        // hi contribution falls outside the last 32 bytes
        out.copy_from_slice(lo);
        return out;
    }
    // hi shifted by whole bytes: the last 32 bytes of (hi || zeros[shift]) is hi[shift..32] followed by zeros
    for i in 0..32 {
        let hi_byte = if i + shift_bytes < 32 {
            hi[i + shift_bytes]
        } else {
            0
        };
        out[i] = lo[i] | hi_byte;
    }
    out
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
fn read_g1_from_limbs(
    lx: &[u8; 32],
    hx: &[u8; 32],
    ly: &[u8; 32],
    hy: &[u8; 32],
) -> Option<G1Point> {
    let shifts = [136usize, 128usize];

    for &shift in &shifts {
        let sbytes = shift / 8;
        // normal order
        let bx = or_with_left_shift_bytes(lx, hx, sbytes);
        let by = or_with_left_shift_bytes(ly, hy, sbytes);
        let px = fq_from_be_bytes(&bx);
        let py = fq_from_be_bytes(&by);
        let aff = ArkG1Affine::new_unchecked(px, py);
        if aff.is_on_curve() && aff.is_in_correct_subgroup_assuming_on_curve() {
            return Some(G1Point { x: aff.x, y: aff.y });
        }

        // XY swap
        let bx = or_with_left_shift_bytes(ly, hy, sbytes);
        let by = or_with_left_shift_bytes(lx, hx, sbytes);
        let px = fq_from_be_bytes(&bx);
        let py = fq_from_be_bytes(&by);
        let aff = ArkG1Affine::new_unchecked(px, py);
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
    let lx = hex_str_to_be32(&vk_fields[i])?;
    let hx = hex_str_to_be32(&vk_fields[i + 1])?;
    let ly = hex_str_to_be32(&vk_fields[i + 2])?;
    let hy = hex_str_to_be32(&vk_fields[i + 3])?;

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
    #[inline(always)]
    fn parse_u64_hex_lsb(s: &str) -> u64 {
        let h = s.trim_start_matches("0x");
        let n = core::cmp::min(16, h.len());
        let slice = &h[h.len() - n..];
        let mut out: u64 = 0;
        for ch in slice.chars() {
            let v = match ch {
                '0'..='9' => ch as u64 - '0' as u64,
                'a'..='f' => 10 + (ch as u64 - 'a' as u64),
                'A'..='F' => 10 + (ch as u64 - 'A' as u64),
                _ => 0,
            };
            out = (out << 4) | v;
        }
        out
    }

    let h0 = parse_u64_hex_lsb(&vk_fields[0]);
    let public_inputs_size = if vk_fields.len() > 1 {
        parse_u64_hex_lsb(&vk_fields[1])
    } else {
        0
    };
    let pub_inputs_offset = if vk_fields.len() > 2 {
        parse_u64_hex_lsb(&vk_fields[2])
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

struct SorobanKeccak {
    env: Env,
}

// Soroban contracts execute on a single-threaded host; marking the adapter as
// Send/Sync is safe because the underlying Env handle is not shared across threads.
unsafe impl Send for SorobanKeccak {}
unsafe impl Sync for SorobanKeccak {}

impl SorobanKeccak {
    fn new(env: &Env) -> Self {
        Self { env: env.clone() }
    }
}

impl HashOps for SorobanKeccak {
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        let env = self.env.clone();
        let input = Bytes::from_slice(&env, data);
        let digest: BytesN<32> = env.crypto().keccak256(&input).into();
        digest.into()
    }
}

struct SorobanBn254 {
    env: Env,
}

unsafe impl Send for SorobanBn254 {}
unsafe impl Sync for SorobanBn254 {}

impl SorobanBn254 {
    fn new(env: &Env) -> Self {
        Self { env: env.clone() }
    }

    fn env(&self) -> Env {
        self.env.clone()
    }

    fn pairing_check_impl(
        &self,
        p0: &ArkG1Affine,
        p1: &ArkG1Affine,
    ) -> Result<bool, StdString> {
        let env = self.env();
        let mut g1_points = SorobanVec::new(&env);
        g1_points.push_back(ark_g1_to_host(&env, p0));
        g1_points.push_back(ark_g1_to_host(&env, p1));

        let mut g2_points = SorobanVec::new(&env);
        g2_points.push_back(ark_g2_to_host(&env, &rhs_g2_affine()));
        g2_points.push_back(ark_g2_to_host(&env, &lhs_g2_affine()));

        Ok(env.crypto().bn254().pairing_check(g1_points, g2_points))
    }
}

impl Bn254Ops for SorobanBn254 {
    fn g1_msm(&self, coms: &[G1Point], scalars: &[ArkFr]) -> Result<ArkG1Affine, StdString> {
        if coms.len() != scalars.len() {
            return Err("commitments / scalars length mismatch".into());
        }
        let env = self.env();
        let bn = env.crypto().bn254();
        let mut acc: Option<HostG1Affine> = None;
        for (pt, scalar) in coms.iter().zip(scalars.iter()) {
            let host_pt = g1_point_to_host(&env, pt);
            let host_scalar = ark_fr_to_host(&env, scalar);
            let term = bn.g1_mul(&host_pt, &host_scalar);
            acc = Some(match acc {
                Some(current) => bn.g1_add(&current, &term),
                None => term,
            });
        }
        match acc {
            Some(result) => host_g1_to_ark(&result),
            None => Ok(ArkG1Affine::identity()),
        }
    }

    fn pairing_check(&self, p0: &ArkG1Affine, p1: &ArkG1Affine) -> bool {
        self.pairing_check_impl(p0, p1).unwrap_or(false)
    }
}

#[contracterror]
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    VkParseError = 1,
    ProofParseError = 2,
    VerificationFailed = 3,
    VkNotSet = 4,
}

#[contractimpl]
impl UltraHonkVerifierContract {
    fn key_vk() -> Symbol {
        symbol_short!("vk")
    }

    fn key_vk_hash() -> Symbol {
        symbol_short!("vk_hash")
    }

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
    /// Verify an UltraHonk proof; on success store proof_id (= soroban sha256(proof_blob))
    pub fn verify_proof(env: Env, vk_json: Bytes, proof_blob: Bytes) -> Result<BytesN<32>, Error> {
        hash::set_soroban_hash_backend(Box::new(SorobanKeccak::new(&env)));
        ec::set_soroban_bn254_backend(Box::new(SorobanBn254::new(&env)));

        let proof_hash: BytesN<32> = env.crypto().keccak256(&proof_blob).into();
        let proof_vec: StdVec<u8> = proof_blob.to_alloc_vec();

        // vk_json → &str  (avoid temporary drop by binding first)
        let vk_vec: StdVec<u8> = vk_json.to_alloc_vec();
        let vk_str = str::from_utf8(&vk_vec).map_err(|_| Error::VkParseError)?;

        // Build VK (manual JSON parser; no serde_json needed)
        let vk = load_vk_from_json_no_serde(vk_str).map_err(|_| Error::VkParseError)?;

        // Verifier (moves vk)
        let verifier = UltraHonkVerifier::new_with_vk(vk);

        // Proof & public inputs (tolerate 440 or 456 field proofs)
        let (pub_inputs_bytes, proof_bytes) = Self::split_inputs_and_proof_bytes(&proof_vec);

        // Verify
        verifier
            .verify(&proof_bytes, &pub_inputs_bytes)
            .map_err(|_| Error::VerificationFailed)?;

        // Persist success
        env.storage().instance().set(&proof_hash, &true);

        Ok(proof_hash)
    }

    /// Set verification key JSON and cache its hash. Returns vk_hash
    pub fn set_vk(env: Env, vk_json: Bytes) -> Result<BytesN<32>, Error> {
        env.storage().instance().set(&Self::key_vk(), &vk_json);
        let hash_bn: BytesN<32> = env.crypto().keccak256(&vk_json).into();
        env.storage().instance().set(&Self::key_vk_hash(), &hash_bn);
        Ok(hash_bn)
    }

    /// Verify using the on-chain stored VK
    pub fn verify_proof_with_stored_vk(env: Env, proof_blob: Bytes) -> Result<BytesN<32>, Error> {
        let vk_json: Bytes = env
            .storage()
            .instance()
            .get(&Self::key_vk())
            .ok_or(Error::VkNotSet)?;
        Self::verify_proof(env, vk_json, proof_blob)
    }

    /// Query if a proof_id was previously verified
    pub fn is_verified(env: Env, proof_id: BytesN<32>) -> bool {
        env.storage().instance().get(&proof_id).unwrap_or(false)
    }
}

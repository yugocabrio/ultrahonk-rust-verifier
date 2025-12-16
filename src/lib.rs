#![no_std]
extern crate alloc;

use alloc::{boxed::Box, string::String as StdString, vec::Vec as StdVec};
use soroban_sdk::{
    contract, contracterror, contractimpl,
    crypto::bn254::{Fr as HostFr, G1Affine as HostG1Affine, G2Affine as HostG2Affine},
    symbol_short, Bytes, BytesN, Env, Symbol, Vec as SorobanVec,
};

use ark_bn254::{Fq, Fq2, G1Affine as ArkG1Affine, G2Affine as ArkG2Affine};
use ark_ff::{PrimeField, Zero};

use ultrahonk_rust_verifier::{
    ec::{self, Bn254Ops},
    field::Fr as ArkFr,
    hash::{self, HashOps},
    types::{G1Point, VerificationKey},
    utils::load_vk_from_json,
    UltraHonkVerifier, PROOF_BYTES,
};

const VK_HEADER_WORDS: usize = 4;
const VK_NUM_G1_POINTS: usize = 28;
const VK_SERIALIZED_LEN: usize = VK_HEADER_WORDS * 8 + VK_NUM_G1_POINTS * 64;

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
    out[..32].copy_from_slice(&fq_to_be_bytes(&pt.x));
    out[32..].copy_from_slice(&fq_to_be_bytes(&pt.y));
    out
}

fn ark_g2_affine_to_bytes(pt: &ArkG2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    out[..32].copy_from_slice(&fq_to_be_bytes(&pt.x.c1));
    out[32..64].copy_from_slice(&fq_to_be_bytes(&pt.x.c0));
    out[64..96].copy_from_slice(&fq_to_be_bytes(&pt.y.c1));
    out[96..].copy_from_slice(&fq_to_be_bytes(&pt.y.c0));
    out
}

fn host_g1_to_ark(pt: &HostG1Affine) -> Result<ArkG1Affine, StdString> {
    let mut bytes = [0u8; 64];
    pt.to_bytes().copy_into_slice(&mut bytes);
    g1_bytes_to_affine(&bytes).map_err(|_| StdString::from("g1"))
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

fn g1_point_to_bytes(pt: &G1Point) -> [u8; 64] {
    if pt.x.is_zero() && pt.y.is_zero() {
        return [0u8; 64];
    }
    let aff = pt.to_affine();
    ark_g1_affine_to_bytes(&aff)
}

fn g1_bytes_to_affine(bytes: &[u8; 64]) -> Result<ArkG1Affine, ()> {
    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&bytes[..32]);
    y_bytes.copy_from_slice(&bytes[32..]);
    let aff = ArkG1Affine::new_unchecked(fq_from_be_bytes(&x_bytes), fq_from_be_bytes(&y_bytes));
    if aff.is_on_curve() && aff.is_in_correct_subgroup_assuming_on_curve() {
        Ok(aff)
    } else {
        Err(())
    }
}

fn g1_point_from_bytes(bytes: &[u8; 64]) -> Result<G1Point, ()> {
    if bytes.iter().all(|b| *b == 0) {
        return Ok(G1Point {
            x: Fq::from(0u64),
            y: Fq::from(0u64),
        });
    }
    let aff = g1_bytes_to_affine(bytes)?;
    Ok(G1Point { x: aff.x, y: aff.y })
}

fn ark_fr_to_host(env: &Env, scalar: &ArkFr) -> HostFr {
    HostFr::from_bytes(BytesN::from_array(env, &scalar.to_bytes()))
}

pub fn serialize_vk_to_bytes(vk: &VerificationKey) -> StdVec<u8> {
    let mut out = StdVec::with_capacity(VK_SERIALIZED_LEN);
    let header = [
        vk.circuit_size,
        vk.log_circuit_size,
        vk.public_inputs_size,
        vk.pub_inputs_offset,
    ];
    for &word in &header {
        out.extend_from_slice(&word.to_be_bytes());
    }

    macro_rules! push_point {
        ($pt:expr) => {{
            let bytes = g1_point_to_bytes(&$pt);
            out.extend_from_slice(&bytes);
        }};
    }

    push_point!(vk.qm);
    push_point!(vk.qc);
    push_point!(vk.ql);
    push_point!(vk.qr);
    push_point!(vk.qo);
    push_point!(vk.q4);
    push_point!(vk.q_lookup);
    push_point!(vk.q_arith);
    push_point!(vk.q_delta_range);
    push_point!(vk.q_elliptic);
    push_point!(vk.q_memory);
    push_point!(vk.q_nnf);
    push_point!(vk.q_poseidon2_external);
    push_point!(vk.q_poseidon2_internal);
    push_point!(vk.s1);
    push_point!(vk.s2);
    push_point!(vk.s3);
    push_point!(vk.s4);
    push_point!(vk.id1);
    push_point!(vk.id2);
    push_point!(vk.id3);
    push_point!(vk.id4);
    push_point!(vk.t1);
    push_point!(vk.t2);
    push_point!(vk.t3);
    push_point!(vk.t4);
    push_point!(vk.lagrange_first);
    push_point!(vk.lagrange_last);

    out
}

fn deserialize_vk_from_bytes(bytes: &[u8]) -> Result<VerificationKey, ()> {
    if bytes.len() != VK_SERIALIZED_LEN {
        return Err(());
    }
    let mut idx = 0usize;
    fn read_u64(bytes: &[u8], idx: &mut usize) -> u64 {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes[*idx..*idx + 8]);
        *idx += 8;
        u64::from_be_bytes(arr)
    }
    fn read_point(bytes: &[u8], idx: &mut usize) -> Result<G1Point, ()> {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes[*idx..*idx + 64]);
        *idx += 64;
        g1_point_from_bytes(&arr)
    }

    let circuit_size = read_u64(bytes, &mut idx);
    let log_circuit_size = read_u64(bytes, &mut idx);
    let public_inputs_size = read_u64(bytes, &mut idx);
    let pub_inputs_offset = read_u64(bytes, &mut idx);

    macro_rules! next_point {
        () => {
            read_point(bytes, &mut idx)?
        };
    }

    Ok(VerificationKey {
        circuit_size,
        log_circuit_size,
        public_inputs_size,
        pub_inputs_offset,
        qm: next_point!(),
        qc: next_point!(),
        ql: next_point!(),
        qr: next_point!(),
        qo: next_point!(),
        q4: next_point!(),
        q_lookup: next_point!(),
        q_arith: next_point!(),
        q_delta_range: next_point!(),
        q_elliptic: next_point!(),
        q_memory: next_point!(),
        q_nnf: next_point!(),
        q_poseidon2_external: next_point!(),
        q_poseidon2_internal: next_point!(),
        s1: next_point!(),
        s2: next_point!(),
        s3: next_point!(),
        s4: next_point!(),
        id1: next_point!(),
        id2: next_point!(),
        id3: next_point!(),
        id4: next_point!(),
        t1: next_point!(),
        t2: next_point!(),
        t3: next_point!(),
        t4: next_point!(),
        lagrange_first: next_point!(),
        lagrange_last: next_point!(),
    })
}

pub fn preprocess_vk_json(vk_json: &str) -> Result<StdVec<u8>, ()> {
    let vk = load_vk_from_json(vk_json);
    Ok(serialize_vk_to_bytes(&vk))
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

    fn pairing_check_impl(&self, p0: &ArkG1Affine, p1: &ArkG1Affine) -> Result<bool, StdString> {
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
            return Err("msm len".into());
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

    fn parse_public_inputs(bytes: &[u8]) -> Result<StdVec<StdVec<u8>>, Error> {
        if bytes.len() % 32 != 0 {
            return Err(Error::ProofParseError);
        }
        let mut out = StdVec::with_capacity(bytes.len() / 32);
        for chunk in bytes.chunks(32) {
            out.push(chunk.to_vec());
        }
        Ok(out)
    }
    /// Verify an UltraHonk proof.
    pub fn verify_proof(
        env: Env,
        vk_bytes: Bytes,
        public_inputs: Bytes,
        proof_bytes: Bytes,
    ) -> Result<(), Error> {
        hash::set_soroban_hash_backend(Box::new(SorobanKeccak::new(&env)));
        ec::set_soroban_bn254_backend(Box::new(SorobanBn254::new(&env)));
        let proof_vec: StdVec<u8> = proof_bytes.to_alloc_vec();
        if proof_vec.len() != PROOF_BYTES {
            return Err(Error::ProofParseError);
        }

        // Deserialize preprocessed verification key bytes
        let vk_vec: StdVec<u8> = vk_bytes.to_alloc_vec();
        let vk = deserialize_vk_from_bytes(&vk_vec).map_err(|_| Error::VkParseError)?;

        // Verifier (moves vk)
        let verifier = UltraHonkVerifier::new_with_vk(vk);

        // Proof & public inputs
        let pub_inputs_bytes = Self::parse_public_inputs(&public_inputs.to_alloc_vec())
            .map_err(|_| Error::ProofParseError)?;

        // Verify
        verifier
            .verify(&proof_vec, &pub_inputs_bytes)
            .map_err(|_| Error::VerificationFailed)?;
        Ok(())
    }

    /// Set preprocessed verification key bytes and cache its hash. Returns vk_hash
    pub fn set_vk(env: Env, vk_bytes: Bytes) -> Result<BytesN<32>, Error> {
        env.storage().instance().set(&Self::key_vk(), &vk_bytes);
        let hash_bn: BytesN<32> = env.crypto().keccak256(&vk_bytes).into();
        env.storage().instance().set(&Self::key_vk_hash(), &hash_bn);
        Ok(hash_bn)
    }

    /// Verify using the on-chain stored VK
    pub fn verify_proof_with_stored_vk(
        env: Env,
        public_inputs: Bytes,
        proof_bytes: Bytes,
    ) -> Result<(), Error> {
        let vk_bytes: Bytes = env
            .storage()
            .instance()
            .get(&Self::key_vk())
            .ok_or(Error::VkNotSet)?;
        Self::verify_proof(env, vk_bytes, public_inputs, proof_bytes)
    }
}

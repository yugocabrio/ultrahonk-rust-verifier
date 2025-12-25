use alloc::string::String as StdString;
use soroban_sdk::{
    crypto::bn254::{Fr as HostFr, G1Affine as HostG1Affine, G2Affine as HostG2Affine},
    Bytes, BytesN, Env, Vec as SorobanVec,
};

use ark_bn254::{Fq, G1Affine as ArkG1Affine, G2Affine as ArkG2Affine};
use ark_ff::PrimeField;
use ultrahonk_rust_verifier::{
    ec::{self, Bn254Ops},
    field::Fr as ArkFr,
    hash::HashOps,
    types::G1Point,
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

pub(crate) fn ark_g1_affine_to_bytes(pt: &ArkG1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&fq_to_be_bytes(&pt.x));
    out[32..].copy_from_slice(&fq_to_be_bytes(&pt.y));
    out
}

pub(crate) fn ark_g2_affine_to_bytes(pt: &ArkG2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    out[..32].copy_from_slice(&fq_to_be_bytes(&pt.x.c1));
    out[32..64].copy_from_slice(&fq_to_be_bytes(&pt.x.c0));
    out[64..96].copy_from_slice(&fq_to_be_bytes(&pt.y.c1));
    out[96..].copy_from_slice(&fq_to_be_bytes(&pt.y.c0));
    out
}

pub(crate) fn host_g1_to_ark(pt: &HostG1Affine) -> Result<ArkG1Affine, StdString> {
    let mut bytes = [0u8; 64];
    pt.to_bytes().copy_into_slice(&mut bytes);
    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&bytes[..32]);
    y_bytes.copy_from_slice(&bytes[32..]);
    let aff = ArkG1Affine::new_unchecked(fq_from_be_bytes(&x_bytes), fq_from_be_bytes(&y_bytes));
    if aff.is_on_curve() && aff.is_in_correct_subgroup_assuming_on_curve() {
        Ok(aff)
    } else {
        Err("g1".into())
    }
}

pub(crate) fn ark_g1_to_host(env: &Env, pt: &ArkG1Affine) -> HostG1Affine {
    let bytes = ark_g1_affine_to_bytes(pt);
    HostG1Affine::from_bytes(BytesN::from_array(env, &bytes))
}

pub(crate) fn ark_g2_to_host(env: &Env, pt: &ArkG2Affine) -> HostG2Affine {
    let bytes = ark_g2_affine_to_bytes(pt);
    HostG2Affine::from_bytes(BytesN::from_array(env, &bytes))
}

pub struct SorobanKeccak {
    env: Env,
}

unsafe impl Send for SorobanKeccak {}
unsafe impl Sync for SorobanKeccak {}

impl SorobanKeccak {
    pub fn new(env: &Env) -> Self {
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

pub struct SorobanBn254 {
    env: Env,
}

unsafe impl Send for SorobanBn254 {}
unsafe impl Sync for SorobanBn254 {}

impl SorobanBn254 {
    pub fn new(env: &Env) -> Self {
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
        g2_points.push_back(ark_g2_to_host(&env, &ec::rhs_g2_affine()));
        g2_points.push_back(ark_g2_to_host(&env, &ec::lhs_g2_affine()));

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
            let host_pt = {
                let aff = pt.to_affine();
                ark_g1_to_host(&env, &aff)
            };
            let host_scalar = HostFr::from_bytes(BytesN::from_array(&env, &scalar.to_bytes()));
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

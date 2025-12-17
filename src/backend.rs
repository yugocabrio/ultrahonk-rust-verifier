use alloc::string::String as StdString;
use soroban_sdk::{
    crypto::bn254::{Fr as HostFr, G1Affine as HostG1Affine, G2Affine as HostG2Affine},
    Bytes, BytesN, Env, Vec as SorobanVec,
};

use ark_bn254::{Fq, Fq2, G1Affine as ArkG1Affine, G2Affine as ArkG2Affine};
use ark_ff::PrimeField;
use ultrahonk_rust_verifier::{ec::Bn254Ops, field::Fr as ArkFr, hash::HashOps, types::G1Point};

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
pub(crate) fn rhs_g2_affine() -> ArkG2Affine {
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
pub(crate) fn lhs_g2_affine() -> ArkG2Affine {
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

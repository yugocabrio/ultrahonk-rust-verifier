use crate::{field::Fr, types::G1Point};

#[cfg(all(feature = "soroban-precompile", not(feature = "std")))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(feature = "std")]
use std::boxed::Box;

use crate::trace;
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, CurveGroup, PrimeGroup};
#[cfg(feature = "trace")]
use ark_ff::BigInteger;
use ark_ff::{One, PrimeField, Zero};

#[cfg(feature = "soroban-precompile")]
use once_cell::race::OnceBox;

/// Trait for BN254 operations used by the verifier hot paths.
/// Implement this to bridge MSM/pairing to a Soroban BN254 precompile.
pub trait Bn254Ops {
    fn g1_msm(&self, coms: &[G1Point], scalars: &[Fr]) -> Result<G1Affine, String>;
    fn pairing_check(&self, p0: &G1Affine, p1: &G1Affine) -> bool;
}

#[inline(always)]
fn affine_checked(pt: &G1Point) -> Result<G1Affine, String> {
    let aff = G1Affine::new_unchecked(pt.x, pt.y);
    if aff.is_on_curve() && aff.is_in_correct_subgroup_assuming_on_curve() {
        Ok(aff)
    } else {
        Err("g1 point not on curve".into())
    }
}

#[inline(always)]
fn negate(pt: &G1Point) -> G1Point {
    G1Point { x: pt.x, y: -pt.y }
}

#[inline(always)]
fn ark_g1_msm(coms: &[G1Point], scalars: &[Fr]) -> Result<G1Affine, String> {
    if coms.len() != scalars.len() {
        return Err("msm len mismatch".into());
    }
    let mut acc = G1Projective::zero();
    trace!("Initial acc: {:?}", acc);
    for (c, s) in coms.iter().zip(scalars.iter()) {
        let aff = G1Affine::new_unchecked(c.x, c.y);
        if !aff.is_on_curve() || !aff.is_in_correct_subgroup_assuming_on_curve() {
            return Err("g1 point invalid".into());
        }
        #[cfg(feature = "trace")]
        {
            trace!(
                "Point.x = 0x{}",
                hex::encode(c.x.into_bigint().to_bytes_be())
            );
            trace!(
                "Point.y = 0x{}",
                hex::encode(c.y.into_bigint().to_bytes_be())
            );
            trace!("Scalar  = 0x{}", hex::encode(s.to_bytes()));
        }
        acc += G1Projective::from(aff).mul_bigint(s.0.into_bigint());
        #[cfg(feature = "trace")]
        {
            let acc_aff = acc.into_affine();
            trace!(
                "Acc.x  = 0x{}",
                hex::encode(acc_aff.x.into_bigint().to_bytes_be())
            );
            trace!(
                "Acc.y  = 0x{}",
                hex::encode(acc_aff.y.into_bigint().to_bytes_be())
            );
            acc = G1Projective::from(acc_aff);
        }
    }
    Ok(acc.into_affine())
}

#[inline(always)]
pub fn rhs_g2_affine() -> G2Affine {
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
    G2Affine::new_unchecked(x, y)
}

#[inline(always)]
pub fn lhs_g2_affine() -> G2Affine {
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
    G2Affine::new_unchecked(x, y)
}

#[inline(always)]
fn ark_pairing_check(p0: &G1Affine, p1: &G1Affine) -> bool {
    let rhs_g2 = rhs_g2_affine();
    let lhs_g2 = lhs_g2_affine();

    let e1 = Bn254::pairing(*p0, rhs_g2);
    let e2 = Bn254::pairing(*p1, lhs_g2);
    e1.0 * e2.0 == <Bn254 as Pairing>::TargetField::one()
}

pub struct ArkworksOps;

impl Bn254Ops for ArkworksOps {
    #[inline(always)]
    fn g1_msm(&self, coms: &[G1Point], scalars: &[Fr]) -> Result<G1Affine, String> {
        ark_g1_msm(coms, scalars)
    }
    #[inline(always)]
    fn pairing_check(&self, p0: &G1Affine, p1: &G1Affine) -> bool {
        ark_pairing_check(p0, p1)
    }
}

static ARKWORKS: ArkworksOps = ArkworksOps;

#[cfg(feature = "soroban-precompile")]
struct BackendHolder(pub Box<dyn Bn254Ops + Send + Sync>);

#[cfg(feature = "soroban-precompile")]
static BACKEND: OnceBox<BackendHolder> = OnceBox::new();

#[inline(always)]
fn backend() -> &'static dyn Bn254Ops {
    #[cfg(feature = "soroban-precompile")]
    {
        if let Some(b) = BACKEND.get() {
            return &*b.0;
        }
    }
    &ARKWORKS
}

/// Multi-scalar multiplication on G1: ∑ sᵢ·Cᵢ
#[inline(always)]
pub fn g1_msm(coms: &[G1Point], scalars: &[Fr]) -> Result<G1Affine, String> {
    backend().g1_msm(coms, scalars)
}

/// Pairing product check e(P0, rhs_g2) * e(P1, lhs_g2) == 1
#[inline(always)]
pub fn pairing_check(p0: &G1Affine, p1: &G1Affine) -> bool {
    backend().pairing_check(p0, p1)
}

pub mod helpers {
    use super::*;
    #[inline(always)]
    pub fn affine_checked(pt: &G1Point) -> Result<G1Affine, String> {
        super::affine_checked(pt)
    }
    #[inline(always)]
    pub fn negate(pt: &G1Point) -> G1Point {
        super::negate(pt)
    }
}

#[cfg(feature = "soroban-precompile")]
/// Register a custom BN254 backend (Soroban BN254 precompile bridge).
pub fn set_backend(ops: Box<dyn Bn254Ops + Send + Sync>) {
    let _ = BACKEND.set(Box::new(BackendHolder(ops)));
}

#[cfg(feature = "soroban-precompile")]
#[inline(always)]
pub fn set_soroban_bn254_backend(ops: Box<dyn Bn254Ops + Send + Sync>) {
    set_backend(ops)
}

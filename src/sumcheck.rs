// src/sumcheck.rs
//! Sum-check verifier
use crate::trace;
use crate::{
    debug::{dbg_fr, dbg_vec},
    field::Fr,
    relations::{accumulate_relation_evaluations, dump_subrelations},
    types::{Transcript, VerificationKey},
};

#[cfg(not(feature = "std"))]
use alloc::{boxed, format, string::String};

#[cfg(feature = "std")]
use lazy_static::lazy_static;

#[cfg(not(feature = "std"))]
use once_cell::race::OnceBox;

#[cfg(feature = "std")]
lazy_static! {
    /// 8-point barycentric coefficients
    static ref BARY: [Fr; 8] = [
        "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51",
        "0x00000000000000000000000000000000000000000000000000000000000002d0",
        "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff11",
        "0x0000000000000000000000000000000000000000000000000000000000000090",
        "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff71",
        "0x00000000000000000000000000000000000000000000000000000000000000f0",
        "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31",
        "0x00000000000000000000000000000000000000000000000000000000000013b0",
    ].map(Fr::from_str);
}

#[cfg(not(feature = "std"))]
static BARY_BOX: OnceBox<[Fr; 8]> = OnceBox::new();

#[cfg(not(feature = "std"))]
fn get_bary() -> &'static [Fr; 8] {
    BARY_BOX.get_or_init(|| {
        alloc::boxed::Box::new([
            Fr::from_str("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51"),
            Fr::from_str("0x00000000000000000000000000000000000000000000000000000000000002d0"),
            Fr::from_str("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff11"),
            Fr::from_str("0x0000000000000000000000000000000000000000000000000000000000000090"),
            Fr::from_str("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff71"),
            Fr::from_str("0x00000000000000000000000000000000000000000000000000000000000000f0"),
            Fr::from_str("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31"),
            Fr::from_str("0x00000000000000000000000000000000000000000000000000000000000013b0"),
        ])
    })
}

/// Check if the sum of two univariates equals the target value
#[inline(always)]
fn check_round_sum(u: &[Fr], target: Fr) -> bool {
    u[0] + u[1] == target
}

/// Calculate next target value for the sum-check
#[inline(always)]
fn next_target(u: &[Fr], chi: Fr) -> Fr {
    // B(χ) = ∏ (χ - i)
    let mut b = Fr::one();
    for i in 0..8 {
        b = b * (chi - Fr::from_u64(i as u64));
    }

    // Σ u_i / (BARY[i] * (χ - i))
    let mut acc = Fr::zero();
    for i in 0..8 {
        #[cfg(feature = "std")]
        let bary_val = BARY[i];
        #[cfg(not(feature = "std"))]
        let bary_val = get_bary()[i];

        let inv = (bary_val * (chi - Fr::from_u64(i as u64))).inverse();
        acc = acc + (u[i] * inv);
    }

    b * acc
}

#[inline(always)]
fn update_pow(pow: Fr, gate_ch: Fr, chi: Fr) -> Fr {
    pow * (Fr::one() + chi * (gate_ch - Fr::one()))
}

pub fn verify_sumcheck(
    proof: &crate::types::Proof,
    tx: &Transcript,
    vk: &VerificationKey,
) -> Result<(), String> {
    let log_n = vk.log_circuit_size as usize;
    let mut target = Fr::zero();
    let mut pow_par = Fr::one();

    trace!("===== SUMCHECK (Rust) =====");
    dbg_fr("initial_target", &target);
    dbg_fr("initial_pow_par", &pow_par);

    // 1) Each round sum check and next target/pow calculation
    for r in 0..log_n {
        let uni = &proof.sumcheck_univariates[r];

        dbg_vec(&format!("u[{r}]"), uni);
        dbg_fr("target_before", &target);

        if !check_round_sum(uni, target) {
            return Err(format!("sum-check round {r}: linear check failed"));
        }

        let chi = tx.sumcheck_u_challenges[r];
        dbg_fr("chi", &chi);

        target = next_target(uni, chi);
        pow_par = update_pow(pow_par, tx.gate_challenges[r], chi);

        dbg_fr("target_after", &target);
        dbg_fr("pow_partial", &pow_par);
        trace!("------------------------------------------");
    }

    // 2) Final relation summation
    let grand = accumulate_relation_evaluations(
        &proof.sumcheck_evaluations,
        &tx.rel_params,
        &tx.alphas,
        pow_par,
    );

    // debug summary
    crate::trace!("===== SUMCHECK DEBUG SUMMARY =====");
    crate::trace!("beta = 0x{}", hex::encode(tx.rel_params.beta.to_bytes()));
    crate::trace!("gamma = 0x{}", hex::encode(tx.rel_params.gamma.to_bytes()));
    crate::trace!("public_inputs_delta = 0x{}", hex::encode(tx.rel_params.public_inputs_delta.to_bytes()));
    crate::trace!("pow_partial = 0x{}", hex::encode(pow_par.to_bytes()));
    crate::trace!("grand_relation_sum = 0x{}", hex::encode(grand.to_bytes()));
    crate::trace!("target = 0x{}", hex::encode(target.to_bytes()));
    crate::trace!("==================================");

    trace!("==== FINAL ====");
    dbg_fr("grand_relation", &grand);
    dbg_fr("target", &target);
    trace!("==============================");

    if grand == target {
        Ok(())
    } else {
        crate::trace!("===== SUMCHECK FINAL CHECK FAILED =====");
        crate::trace!("grand_relation = 0x{}", hex::encode(grand.to_bytes()));
        crate::trace!("target = 0x{}", hex::encode(target.to_bytes()));
        crate::trace!("difference = 0x{}", hex::encode((grand - target).to_bytes()));
        crate::trace!("======================================");
        Err("Final relation ≠ target".into())
    }
}

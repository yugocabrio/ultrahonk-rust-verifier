//! Sum-check verifier ― Ultra-/Plonk‐Honk compatible
//! -------------------------------------------------

use crate::{
    debug::{dbg_fr, dbg_vec},
    field::Fr,
    relations::{accumulate_relation_evaluations, dump_subrelations},
    types::{Transcript, VerificationKey},
};
use crate::trace;
use hex;

lazy_static::lazy_static! {
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
        let inv = (BARY[i] * (chi - Fr::from_u64(i as u64))).inverse();
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
    let log_n       = vk.log_circuit_size as usize;
    let mut target  = Fr::zero();
    let mut pow_par = Fr::one();

    trace!("===== SUMCHECK (Rust) =====");
    dbg_fr("initial_target" , &target);
    dbg_fr("initial_pow_par", &pow_par);

    // 1) 각 라운드 합산 검사 및 다음 target/pow 계산
    for r in 0..log_n {
        let uni = &proof.sumcheck_univariates[r];

        dbg_vec(&format!("u[{r}]"     ), uni);
        dbg_fr ("target_before"       , &target);

        if !check_round_sum(uni, target) {
            return Err(format!("sum-check round {r}: linear check failed"));
        }

        let chi = tx.sumcheck_u_challenges[r];
        dbg_fr("chi", &chi);

        target  = next_target(uni, chi);
        pow_par = update_pow(pow_par, tx.gate_challenges[r], chi);

        dbg_fr("target_after" , &target);
        dbg_fr("pow_partial"  , &pow_par);
        trace!("------------------------------------------");
    }

    // 2) 최종 relation 합산
    let grand = accumulate_relation_evaluations(
        &proof.sumcheck_evaluations,
        &tx.rel_params,
        &tx.alphas,
        pow_par,
    );

    // debug summary
    #[cfg(feature = "trace")]
    {
        trace!("---- DEBUG SUMMARY ---------------------------------");
        trace!("beta               = 0x{}", hex::encode(tx.rel_params.beta.to_bytes()));
        trace!("gamma              = 0x{}", hex::encode(tx.rel_params.gamma.to_bytes()));
        trace!(
            "public_inputs_delta= 0x{}",
            hex::encode(tx.rel_params.public_inputs_delta.to_bytes())
        );
        trace!("pow_partial        = 0x{}", hex::encode(pow_par.to_bytes()));
        trace!("grand_relation_sum = 0x{}", hex::encode(grand.to_bytes()));
        trace!("target             = 0x{}", hex::encode(target.to_bytes()));
        dump_subrelations(
            &proof.sumcheck_evaluations,
            &tx.rel_params,
            &tx.alphas,
            pow_par,
        );
        trace!("----------------------------------------------------");
    }

    trace!("==== FINAL ====");
    dbg_fr("grand_relation", &grand);
    dbg_fr("target"        , &target);
    trace!("==============================");

    if grand == target {
        Ok(())
    } else {
        Err("Final relation ≠ target".into())
    }
}

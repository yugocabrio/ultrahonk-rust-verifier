//! Sum-check verifier
use crate::{
    field::Fr,
    relations::accumulate_relation_evaluations,
    types::{Transcript, VerificationKey, BATCHED_RELATION_PARTIAL_LENGTH},
};

#[cfg(feature = "std")]
use lazy_static::lazy_static;

#[cfg(not(feature = "std"))]
use once_cell::race::OnceBox;

#[cfg(feature = "std")]
lazy_static! {
    /// Barycentric coefficients
    static ref BARY: [Fr; BATCHED_RELATION_PARTIAL_LENGTH] = [
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
static BARY_BOX: OnceBox<[Fr; BATCHED_RELATION_PARTIAL_LENGTH]> = OnceBox::new();

#[cfg(not(feature = "std"))]
fn get_bary() -> &'static [Fr; BATCHED_RELATION_PARTIAL_LENGTH] {
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
fn check_sum(round_univariate: &[Fr], round_target: Fr) -> bool {
    let total_sum = round_univariate[0] + round_univariate[1];
    total_sum == round_target
}

/// Calculate next target value for the sum-check
#[inline(always)]
fn compute_next_target_sum(
    round_univariate: &[Fr],
    round_challenge: Fr,
) -> Result<Fr, &'static str> {
    // B(χ) = ∏ (χ - i)
    let mut b_poly = Fr::one();
    for i in 0..BATCHED_RELATION_PARTIAL_LENGTH {
        b_poly = b_poly * (round_challenge - Fr::from_u64(i as u64));
    }

    // Σ u_i / (BARY[i] * (χ - i))
    let mut acc = Fr::zero();
    for i in 0..BATCHED_RELATION_PARTIAL_LENGTH {
        #[cfg(feature = "std")]
        let bary_val = BARY[i];
        #[cfg(not(feature = "std"))]
        let bary_val = get_bary()[i];

        let denom = bary_val * (round_challenge - Fr::from_u64(i as u64));
        let inv = denom.inverse().ok_or("denom zero")?;
        acc = acc + (round_univariate[i] * inv);
    }

    Ok(b_poly * acc)
}

#[inline(always)]
fn partially_evaluate_pow(
    gate_challenge: Fr,
    pow_partial_evaluation: Fr,
    round_challenge: Fr,
) -> Fr {
    pow_partial_evaluation * (Fr::one() + round_challenge * (gate_challenge - Fr::one()))
}

pub fn verify_sumcheck(
    proof: &crate::types::Proof,
    tp: &Transcript,
    vk: &VerificationKey,
) -> Result<(), &'static str> {
    let log_n = vk.log_circuit_size as usize;
    let mut round_target = Fr::zero();
    let mut pow_partial_evaluation = Fr::one();

    // 1) Each round sum check and next target/pow calculation
    for round in 0..log_n {
        let round_univariate = &proof.sumcheck_univariates[round];

        if !check_sum(round_univariate, round_target) {
            return Err("round failed");
        }

        let round_challenge = tp.sumcheck_u_challenges[round];
        round_target = compute_next_target_sum(round_univariate, round_challenge)?;
        pow_partial_evaluation = partially_evaluate_pow(
            tp.gate_challenges[round],
            pow_partial_evaluation,
            round_challenge,
        );
    }

    // 2) Final relation summation
    let grand_honk_relation_sum = accumulate_relation_evaluations(
        &proof.sumcheck_evaluations,
        &tp.rel_params,
        &tp.alphas,
        pow_partial_evaluation,
    );

    if grand_honk_relation_sum == round_target {
        Ok(())
    } else {
        crate::trace!("===== SUMCHECK FINAL CHECK FAILED =====");
        crate::trace!(
            "grand_relation = 0x{}",
            hex::encode(grand_honk_relation_sum.to_bytes())
        );
        crate::trace!("target = 0x{}", hex::encode(round_target.to_bytes()));
        crate::trace!(
            "difference = 0x{}",
            hex::encode((grand_honk_relation_sum - round_target).to_bytes())
        );
        crate::trace!("======================================");
        Err("sumcheck final mismatch")
    }
}

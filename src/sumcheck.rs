//! Sumcheck verification

use crate::field::Fr;
use crate::relations::accumulate_relation_evaluations;
use crate::types::{Transcript, VerificationKey};
use lazy_static::lazy_static;

lazy_static! {
    /// Barycentric Lagrange denominators for 8‐point domain (from TS).
    static ref BARYCENTRIC_LAGRANGE_DENOMINATORS: [Fr; 8] = [
        Fr::from_str("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51"),
        Fr::from_str("0x00000000000000000000000000000000000000000000000000000000000002d0"),
        Fr::from_str("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff11"),
        Fr::from_str("0x0000000000000000000000000000000000000000000000000000000000000090"),
        Fr::from_str("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff71"),
        Fr::from_str("0x00000000000000000000000000000000000000000000000000000000000000f0"),
        Fr::from_str("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31"),
        Fr::from_str("0x00000000000000000000000000000000000000000000000000000000000013b0"),
    ];
}

/// Check that round_univar[0] + round_univar[1] == target.
fn check_sum(round_univar: &[Fr], target: Fr) -> bool {
    let sum = round_univar[0] + round_univar[1];
    sum == target
}

/// Compute next sumcheck target via barycentric formula.
fn compute_next_target(round_univar: &[Fr], challenge: Fr) -> Fr {
    // numerator = ∏_{i=0..7}(challenge − i)
    let mut numerator = Fr::one();
    for i in 0..8 {
        numerator = numerator * (challenge - Fr::from_u64(i));
    }

    // Σ u_i / (D_i · (challenge − i))  =  Σ u_i · ((D_i · (challenge − i))⁻¹)
    let mut accumulator = Fr::zero();
    for i in 0..8u64 {
        let denom = BARYCENTRIC_LAGRANGE_DENOMINATORS[i as usize] * (challenge - Fr::from_u64(i));
        let inv   = denom.inverse();                    // 1 / (D_i · (challenge − i))
        accumulator = accumulator + round_univar[i as usize] * inv;
    }

    numerator * accumulator
}

/// Update running "pow_partial_eval" for each round.
fn update_pow_partial(eval: Fr, gate_ch: Fr, challenge: Fr) -> Fr {
    let term = Fr::one() + (challenge * (gate_ch - Fr::one()));
    eval * term
}

/// Verify the sumcheck phase. Returns Err(msg) on failure.
pub fn verify_sumcheck(
    proof: &crate::types::Proof,
    tx: &Transcript,
    vk: &VerificationKey,
) -> Result<(), String> {
    let mut target = Fr::zero();
    let mut pow_partial = Fr::one();
    let log_n = vk.log_circuit_size as usize;

    // 1) Check each round's low-degree sum and prepare next target
    for round in 0..log_n {
        let univar = &proof.sumcheck_univariates[round];
        if !check_sum(univar, target) {
            return Err(format!("Sumcheck first-pass failed at round {}", round));
        }
        let challenge = tx.sumcheck_u_challenges[round];
        target = compute_next_target(univar, challenge);
        pow_partial = update_pow_partial(pow_partial, tx.gate_challenges[round], challenge);
    }

    // 2) Accumulate all relation evaluations and compare with target
    let grand = accumulate_relation_evaluations(
        &proof.sumcheck_evaluations,
        &tx.rel_params,
        &tx.alphas,
        pow_partial,
    );

    if grand != target {
        Err("Final relation aggregate ≠ sumcheck target".into())
    } else {
        Ok(())
    }
}

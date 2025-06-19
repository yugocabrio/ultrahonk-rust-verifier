//! Sum-check verifier ― Ultra-/Plonk‐Honk compatible
//! -------------------------------------------------

use crate::{
    field::Fr,
    relations::accumulate_relation_evaluations,
    types::{Transcript, VerificationKey},
};

/// 8-point barycentricラグランジュ係数（TS と byte-perfect 同一）
const BARYCENTRIC: [&str; 8] = [
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51",
    "0x00000000000000000000000000000000000000000000000000000000000002d0",
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff11",
    "0x0000000000000000000000000000000000000000000000000000000000000090",
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff71",
    "0x00000000000000000000000000000000000000000000000000000000000000f0",
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31",
    "0x00000000000000000000000000000000000000000000000000000000000013b0",
];

lazy_static::lazy_static! {
    static ref BARY: [Fr; 8] = BARYCENTRIC.map(Fr::from_str);
}

/// --- helpers -------------------------------------------------------------

/// u₀+u₁ が target と一致するか
#[inline(always)]
fn check_round_sum(u: &[Fr], target: Fr) -> bool {
    u[0] + u[1] == target
}

/// 次ラウンドの target を計算（barycentric 補間）
fn next_target(u: &[Fr], χ: Fr) -> Fr {
    // B(χ)  = ∏(χ-i)
    let mut b = Fr::one();
    for i in 0..8 {
        b = b * (χ - Fr::from_u64(i as u64));
    }

    // Σ u_i / (D_i·(χ-i))
    let mut acc = Fr::zero();
    for i in 0..8 {
        let inv = (BARY[i] * (χ - Fr::from_u64(i as u64))).inverse();
        acc = acc + u[i] * inv;
    }
    b * acc
}

/// POW の部分評価を 1 ラウンド進める
#[inline(always)]
fn update_pow(pow: Fr, gate_ch: Fr, χ: Fr) -> Fr {
    pow * (Fr::one() + χ * (gate_ch - Fr::one()))
}

/// --- public API ----------------------------------------------------------

/// Returns `Ok(())` if the sum-check passes, otherwise `Err(msg)`.
pub fn verify_sumcheck(
    proof: &crate::types::Proof,
    tx: &Transcript,
    vk: &VerificationKey,
) -> Result<(), String> {
    let log_n = vk.log_circuit_size as usize;
    let mut target     = Fr::zero();
    let mut pow_partial = Fr::one();

    // ── (1) round reductions ────────────────────────────────────────────
    for r in 0..log_n {
        let uni = &proof.sumcheck_univariates[r];

        if !check_round_sum(uni, target) {
            return Err(format!("sum-check round {r}: linear check failed"));
        }
        let χ = tx.sumcheck_u_challenges[r];
        target      = next_target(uni, χ);
        pow_partial = update_pow(pow_partial, tx.gate_challenges[r], χ);
    }

    // ── (2) relation evaluations ────────────────────────────────────────
    let grand = accumulate_relation_evaluations(
        &proof.sumcheck_evaluations,
        &tx.rel_params,
        &tx.alphas,
        pow_partial,
    );

    if grand == target {
        Ok(())
    } else {
        Err("Final relation aggregate ≠ sumcheck target".into())
    }
}

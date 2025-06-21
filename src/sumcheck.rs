//! Sum-check verifier ― Ultra-/Plonk‐Honk compatible
//! -------------------------------------------------

use crate::{
    debug::{dbg_fr, dbg_vec},
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

    use crate::debug::{dbg_fr, dbg_vec};   // ① 先ほどのユーティリティをインポート

    let log_n       = vk.log_circuit_size as usize;
    let mut target  = Fr::zero();
    let mut pow_par = Fr::one();

    println!("===== SUMCHECK (Rust) =====");
    dbg_fr ("initial_target" , &target);
    dbg_fr ("initial_pow_par", &pow_par);

    // ──── 1) round reductions ─────────────────────────────
    for r in 0..log_n {
        let uni = &proof.sumcheck_univariates[r];

        dbg_vec(&format!("u[{r}]"), uni);             // ② 各ラウンドの多項式係数
        dbg_fr ("target_before" , &target);

        if !check_round_sum(uni, target) {
            return Err(format!("sum-check round {r}: linear check failed"));
        }

        let χ = tx.sumcheck_u_challenges[r];
        dbg_fr ("χ" , &χ);

        target   = next_target(uni, χ);
        pow_par  = update_pow(pow_par, tx.gate_challenges[r], χ);

        dbg_fr ("target_after"  , &target);
        dbg_fr ("pow_partial"   , &pow_par);
        println!("------------------------------------------");
    }

    // ──── 2) terminal relation check ─────────────────────
    let grand = accumulate_relation_evaluations(
        &proof.sumcheck_evaluations,
        &tx.rel_params,
        &tx.alphas,
        pow_par,
    );


    {
        use crate::relations::dump_subrelations;
        println!("---- DEBUG SUMMARY ---------------------------------");
        println!("beta               = 0x{}", hex::encode(tx.rel_params.beta.to_bytes()));
        println!("gamma              = 0x{}", hex::encode(tx.rel_params.gamma.to_bytes()));
        println!("public_inputs_delta= 0x{}", hex::encode(tx.rel_params.public_inputs_delta.to_bytes()));
        println!("pow_partial        = 0x{}", hex::encode(pow_par.to_bytes()));
        println!("grand_relation_sum = 0x{}", hex::encode(grand.to_bytes()));
        println!("target             = 0x{}", hex::encode(target.to_bytes()));
        dump_subrelations(
            &proof.sumcheck_evaluations,
            &tx.rel_params,
            &tx.alphas,
            pow_par,
        );
        println!("----------------------------------------------------");
    }
    

    println!("==== FINAL ====");
    dbg_fr("grand_relation", &grand);
    dbg_fr("target"        , &target);
    println!("==============================");

    if grand == target { Ok(()) } else { Err("Final relation ≠ target".into()) }
}

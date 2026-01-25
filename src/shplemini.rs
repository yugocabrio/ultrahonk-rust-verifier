//! Shplemini batch-opening verifier for BN254
use crate::ec::helpers::negate;
use crate::ec::{g1_msm, pairing_check};
use crate::field::Fr;
use crate::trace;
use crate::types::{
    G1Point, Proof, Transcript, VerificationKey, CONST_PROOF_SIZE_LOG_N, NUMBER_OF_ENTITIES,
    NUMBER_TO_BE_SHIFTED, NUMBER_UNSHIFTED,
};
use soroban_sdk::Env;

/// Shplemini verification
pub fn verify_shplemini(
    env: &Env,
    proof: &Proof,
    vk: &VerificationKey,
    tp: &Transcript,
) -> Result<(), &'static str> {
    // 1) r^{2^i}
    let log_n = vk.log_circuit_size as usize;
    let mut r_pows = [Fr::zero(); CONST_PROOF_SIZE_LOG_N];
    r_pows[0] = tp.gemini_r;
    for i in 1..log_n {
        r_pows[i] = r_pows[i - 1] * r_pows[i - 1];
    }
    // 2) allocate arrays
    // Match Solidity sizing: NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 2
    // Layout:
    //   [0]                 = shplonk_Q
    //   [1..=40]            = VK + proof entities (NUMBER_OF_ENTITIES)
    //   [41..=67]           = gemini_fold_comms (CONST_PROOF_SIZE_LOG_N - 1 = 27)
    //   [68]                = generator (1,2) with const_acc scalar
    //   [69]                = kzg_quotient with scalar z
    const TOTAL: usize = 1 + NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 1;
    trace!("total = {}", TOTAL);
    let mut scalars = [Fr::zero(); TOTAL];
    let mut coms = [G1Point::infinity(); TOTAL];

    // 3) compute shplonk weights
    let pos0 = (tp.shplonk_z - r_pows[0])
        .inverse()
        .ok_or("shplonk denominator (z - r^0) is zero")?;
    let neg0 = (tp.shplonk_z + r_pows[0])
        .inverse()
        .ok_or("shplonk denominator (z + r^0) is zero")?;
    let unshifted = pos0 + tp.shplonk_nu * neg0;
    let gemini_r_inv = tp.gemini_r.inverse().ok_or("gemini_r challenge is zero")?;
    let shifted = gemini_r_inv * (pos0 - tp.shplonk_nu * neg0);
    // 4) shplonk_Q
    scalars[0] = Fr::one();
    coms[0] = proof.shplonk_q.clone();

    // 5) weight sumcheck evals
    let mut rho_pow = Fr::one();
    let mut eval_acc = Fr::zero();
    let shifted_end = NUMBER_UNSHIFTED + NUMBER_TO_BE_SHIFTED;
    debug_assert_eq!(NUMBER_OF_ENTITIES, shifted_end);
    for (idx, eval) in proof
        .sumcheck_evaluations
        .iter()
        .take(NUMBER_OF_ENTITIES)
        .enumerate()
    {
        let scalar = if idx < NUMBER_UNSHIFTED {
            -unshifted
        } else {
            -shifted
        } * rho_pow;
        scalars[1 + idx] = scalar;
        eval_acc = eval_acc + (*eval * rho_pow);
        rho_pow = rho_pow * tp.rho;
    }
    // 6) load VK & proof
    {
        let mut j = 1;
        macro_rules! push {
            ($f:ident) => {{
                coms[j] = vk.$f.clone();
                j += 1;
            }};
        }
        push!(qm);
        push!(qc);
        push!(ql);
        push!(qr);
        push!(qo);
        push!(q4);
        // Match Solidity VK commitment order strictly
        // 7..13: qLookup, qArith, qDeltaRange, qElliptic, qAux, qPoseidon2External, qPoseidon2Internal
        push!(q_lookup);
        push!(q_arith);
        push!(q_delta_range);
        push!(q_elliptic);
        push!(q_aux);
        push!(q_poseidon2_external);
        push!(q_poseidon2_internal);
        push!(s1);
        push!(s2);
        push!(s3);
        push!(s4);
        push!(id1);
        push!(id2);
        push!(id3);
        push!(id4);
        push!(t1);
        push!(t2);
        push!(t3);
        push!(t4);
        push!(lagrange_first);
        push!(lagrange_last);

        coms[j] = proof.w1.clone();
        j += 1;
        coms[j] = proof.w2.clone();
        j += 1;
        coms[j] = proof.w3.clone();
        j += 1;
        coms[j] = proof.w4.clone();
        j += 1;
        coms[j] = proof.z_perm.clone();
        j += 1;
        coms[j] = proof.lookup_inverses.clone();
        j += 1;
        coms[j] = proof.lookup_read_counts.clone();
        j += 1;
        coms[j] = proof.lookup_read_tags.clone();
        j += 1;

        coms[j] = proof.w1.clone();
        j += 1;
        coms[j] = proof.w2.clone();
        j += 1;
        coms[j] = proof.w3.clone();
        j += 1;
        coms[j] = proof.w4.clone();
        j += 1;
        coms[j] = proof.z_perm.clone();
        j += 1;
        let _ = j; // silence "assigned but never read" in non-trace builds
    }

    // 7) folding rounds
    let mut fold_pos = [Fr::zero(); CONST_PROOF_SIZE_LOG_N];
    let mut cur = eval_acc;
    for j in (1..=log_n).rev() {
        let r2 = r_pows[j - 1];
        let u = tp.sumcheck_u_challenges[j - 1];
        let num = r2 * cur * Fr::from_u64(2)
            - proof.gemini_a_evaluations[j - 1] * (r2 * (Fr::one() - u) - u);
        let den = r2 * (Fr::one() - u) + u;
        let den_inv = den.inverse().ok_or("fold round denominator is zero")?;
        cur = num * den_inv;
        fold_pos[j - 1] = cur;
    }
    // 8) accumulate constant term
    let mut const_acc = fold_pos[0] * pos0 + proof.gemini_a_evaluations[0] * tp.shplonk_nu * neg0;
    let mut v_pow = tp.shplonk_nu * tp.shplonk_nu;
    // 9) further folding + commit
    // Base index where fold commitments start
    let base = 1 + NUMBER_OF_ENTITIES;
    for j in 1..log_n {
        let pos_inv = (tp.shplonk_z - r_pows[j])
            .inverse()
            .ok_or("shplonk denominator (z - r^i) is zero")?;
        let neg_inv = (tp.shplonk_z + r_pows[j])
            .inverse()
            .ok_or("shplonk denominator (z + r^i) is zero")?;
        let sp = v_pow * pos_inv;
        let sn = v_pow * tp.shplonk_nu * neg_inv;

        scalars[base + j - 1] = -(sp + sn);
        const_acc = const_acc + proof.gemini_a_evaluations[j] * sn + fold_pos[j] * sp;

        v_pow = v_pow * tp.shplonk_nu * tp.shplonk_nu;

        coms[base + j - 1] = proof.gemini_fold_comms[j - 1].clone();
    }

    // Fill remaining (dummy) fold commitments so MSM layout matches Solidity (total 27 entries)
    for i in (log_n - 1)..(CONST_PROOF_SIZE_LOG_N - 1) {
        coms[base + i] = proof.gemini_fold_comms[i].clone();
    }

    // 10) add generator
    // Generator goes right after all fold commitments (27 entries)
    let one_idx = base + (CONST_PROOF_SIZE_LOG_N - 1);
    trace!("one_idx = {}", one_idx);
    coms[one_idx] = G1Point::generator();
    scalars[one_idx] = const_acc;

    // 11) add quotient
    let q_idx = one_idx + 1;
    trace!("q_idx = {}", q_idx);
    coms[q_idx] = proof.kzg_quotient.clone();
    scalars[q_idx] = tp.shplonk_z;

    // 12) MSM + pairing
    let p0 = g1_msm(env, &coms, &scalars)?;
    let p1 = negate(env, &proof.kzg_quotient);
    if pairing_check(env, &p0, &p1) {
        Ok(())
    } else {
        Err("Shplonk pairing check failed")
    }
}

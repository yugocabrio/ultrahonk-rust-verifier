// src/shplonk.rs

use crate::field::Fr;
use crate::types::{G1Point, VerificationKey, Proof, Transcript};
use ark_bn254::{Bn254, G1Affine, G1Projective, G2Projective, Fq, Fq2};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ec::pairing::Pairing;
use ark_ff::{Zero, One};
use std::str::FromStr;
use std::ops::Mul;

pub const NUMBER_UNSHIFTED: usize = 35;
pub const NUMBER_SHIFTED:   usize = 5;   // = 40 - 35

/// Negate a G1 point (needed for moving quotient commitment to the other side).
fn negate(pt: &G1Point) -> G1Point {
    let proj = G1Projective::from(G1Affine::new_unchecked(pt.x, pt.y));
    let neg_affine = (-proj).into_affine();
    G1Point { x: neg_affine.x, y: neg_affine.y }
}

/// Multi‐scalar‐multiply on G1: ∑ scalars[i] * coms[i].
fn batch_mul(coms: &[G1Point], scalars: &[Fr]) -> G1Point {
    let mut acc = G1Projective::zero();
    for (c, s) in coms.iter().zip(scalars.iter()) {
        if !s.is_zero() {
            let pg = G1Affine::new_unchecked(c.x, c.y);
            acc += pg.mul(s.0);
        }
    }
    let a = acc.into_affine();
    G1Point { x: a.x, y: a.y }
}

/// Perform the final pairing check e(P0, G2)·e(P1, vk_g2) == 1.
fn pairing_check(p0: &G1Point, p1: &G1Point) -> bool {
    // standard BN254 G2 generator
    let g2 = G2Projective::generator().into_affine();
    // hardcoded second G2 from TS verifier
    let vk_g2 = G2Projective::new(
        Fq2::new(
            Fq::from_str("0x260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1").unwrap(),
            Fq::from_str("0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed").unwrap(),
        ),
        Fq2::new(
            Fq::from_str("0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b").unwrap(),
            Fq::from_str("0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa").unwrap(),
        ),
        Fq2::one(),
    )
    .into_affine();

    let g1_p0 = G1Affine::new_unchecked(p0.x, p0.y);
    let g1_p1 = G1Affine::new_unchecked(p1.x, p1.y);
    let e1 = Bn254::pairing(g1_p0, g2);
    let e2 = Bn254::pairing(g1_p1, vk_g2);
    e1.0 * e2.0 == <Bn254 as Pairing>::TargetField::one()
}

/// Verify Shplonk: batch all checks into one MSM+pairing.
pub fn verify_shplonk(
    proof: &Proof,
    vk: &VerificationKey,
    tx: &Transcript,
) -> Result<(), String> {
    let log_n = vk.log_circuit_size as usize;
    let n_sum = proof.sumcheck_evaluations.len(); // should be 40

    // 1) Precompute r^(2^i)
    let mut powers = Vec::with_capacity(log_n);
    powers.push(tx.gemini_r);
    for i in 1..log_n {
        powers.push(powers[i - 1] * powers[i - 1]);
    }

    // 2) Prepare arrays: 1 Q, n_sum evals, VK+proof commitments (40), log_n folds, const, quotient
    let total = 1 + n_sum + 40 + log_n + 1 + 1;
    let mut scalars = vec![Fr::zero(); total];
    let mut coms    = vec![G1Point { x: Fq::zero(), y: Fq::zero() }; total];

    // 3) Compute the "unshifted" / "shifted" batching scalars (pos/neg inverses)
    let pos0 = (tx.shplonk_z - powers[0]).inverse();
    let neg0 = (tx.shplonk_z + powers[0]).inverse();
    let unshifted = pos0 + tx.shplonk_nu * neg0;
    let shifted   = tx.gemini_r.inverse() * (pos0 - tx.shplonk_nu * neg0);

    // 4) Index 0 ← shplonk_Q
    scalars[0] = Fr::one();
    coms[0]    = proof.shplonk_q.clone();

    // 5) Batch sumcheck_evaluations with ρ–powers
    let mut running = Fr::one();
    let mut acc_eval = Fr::zero();
    // unshifted over first half
    for i in 0..NUMBER_UNSHIFTED {           // 0..34
        let idx = 1 + i;
        scalars[idx] = (-unshifted) * running;
        acc_eval = acc_eval + proof.sumcheck_evaluations[i] * running;
        running = running * tx.rho;
    }
    // shifted over second half
    for i in NUMBER_UNSHIFTED..n_sum {       // 35..39
        let idx = 1 + i;
        scalars[idx] = (-shifted) * running;
        acc_eval = acc_eval + proof.sumcheck_evaluations[i] * running;
        running = running * tx.rho;
    }

    // 6) Load all VK commitments (selectors, wires, tables, Lagrange)
    let mut i = 1 + n_sum;
    macro_rules! load_vk { ($field:ident) => {
        coms[i] = vk.$field.clone(); i += 1;
    }}
    load_vk!(qm); load_vk!(qc); load_vk!(ql); load_vk!(qr);
    load_vk!(qo); load_vk!(q4); load_vk!(q_lookup); load_vk!(q_arith);
    load_vk!(q_range); load_vk!(q_aux); load_vk!(q_elliptic);
    load_vk!(q_poseidon2_external); load_vk!(q_poseidon2_internal);
    load_vk!(s1); load_vk!(s2); load_vk!(s3); load_vk!(s4);
    load_vk!(id1); load_vk!(id2); load_vk!(id3); load_vk!(id4);
    load_vk!(t1); load_vk!(t2); load_vk!(t3); load_vk!(t4);
    load_vk!(lagrange_first); load_vk!(lagrange_last);

    // 7) Load proof's wire & lookup commitments
    coms[i] = proof.w1.clone(); i += 1;
    coms[i] = proof.w2.clone(); i += 1;
    coms[i] = proof.w3.clone(); i += 1;
    coms[i] = proof.w4.clone(); i += 1;
    coms[i] = proof.z_perm.clone(); i += 1;
    coms[i] = proof.lookup_inverses.clone(); i += 1;
    coms[i] = proof.lookup_read_counts.clone(); i += 1;
    coms[i] = proof.lookup_read_tags.clone(); i += 1;

    // 8) Load "shifted" wire commitments (same order)
    coms[i] = proof.w1.clone(); i += 1;
    coms[i] = proof.w2.clone(); i += 1;
    coms[i] = proof.w3.clone(); i += 1;
    coms[i] = proof.w4.clone(); i += 1;
    coms[i] = proof.z_perm.clone(); i += 1;

    // 9) Gemini folding: compute fold‐position evaluations
    let mut fold_pos = vec![Fr::zero(); log_n];
    let mut cur_acc  = acc_eval;
    for j in (1..=log_n).rev() {
        let r2 = powers[j - 1];
        let u  = tx.sumcheck_u_challenges[j - 1];
        let num = r2 * cur_acc * Fr::from_u64(2)
            - proof.gemini_a_evaluations[j - 1] * (r2 * (Fr::one() - u) - u);
        let den = r2 * (Fr::one() - u) + u;
        let next = num * den.inverse();
        fold_pos[j - 1] = next;
        cur_acc = next;
    }

    // 10) Constant‐term accumulation
    let mut const_acc = fold_pos[0] * pos0
        + proof.gemini_a_evaluations[0] * tx.shplonk_nu * neg0;
    running = tx.shplonk_nu * tx.shplonk_nu;

    // 11) Fold commitments
    let base = 1 + n_sum + 40;
    for j in 1..log_n {
        let pi = powers[j];
        let pos_i = (tx.shplonk_z - pi).inverse();
        let neg_i = (tx.shplonk_z + pi).inverse();
        let sp = running * pos_i;
        let sn = running * tx.shplonk_nu * neg_i;
        let idx = base + (j - 1);
        scalars[idx] = (-sp) + (-sn);
        const_acc = const_acc + proof.gemini_a_evaluations[j] * sn + fold_pos[j] * sp;
        running   = running * tx.shplonk_nu * tx.shplonk_nu;
        coms[idx] = proof.gemini_fold_comms[j - 1].clone();
    }

    // 12) "1‐point" at G1::one() and its scalar = const_acc
    let const_idx = 1 + n_sum + 40 + log_n;
    let gen = G1Projective::generator();
    coms[const_idx]    = G1Point { x: gen.x, y: gen.y };
    scalars[const_idx] = const_acc;

    // 13) Quotient commitment at last index, scalar = z
    let q_idx = const_idx + 1;
    coms[q_idx]    = proof.kzg_quotient.clone();
    scalars[q_idx] = tx.shplonk_z;

    // 14) Run MSM + pairing
    let p0 = batch_mul(&coms, &scalars);
    let p1 = negate(&proof.kzg_quotient);
    if pairing_check(&p0, &p1) {
        Ok(())
    } else {
        Err("Shplonk pairing check failed".into())
    }
}

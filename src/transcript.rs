//! Fiat–Shamir transcript for UltraHonk

use crate::trace;
use crate::{
    field::Fr,
    hash::hash32,
    types::{Proof, RelationParameters, Transcript, CONST_PROOF_SIZE_LOG_N},
};
use ark_bn254::G1Affine;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

fn push_point(buf: &mut Vec<u8>, pt: &G1Affine) {
    // Serialize an Fq coordinate into two bn254::Fr limbs (lo136, hi<=118)
    use crate::utils::fq_to_halves_be;
    let (x_lo, x_hi) = fq_to_halves_be(&pt.x);
    let (y_lo, y_hi) = fq_to_halves_be(&pt.y);
    buf.extend_from_slice(&x_lo);
    buf.extend_from_slice(&x_hi);
    buf.extend_from_slice(&y_lo);
    buf.extend_from_slice(&y_hi);
}

fn split_challenge(fr: Fr) -> (Fr, Fr) {
    let b = fr.to_bytes();
    let mut lo = [0u8; 32];
    lo[16..].copy_from_slice(&b[16..]);
    let mut hi = [0u8; 32];
    hi[16..].copy_from_slice(&b[..16]);
    (Fr::from_bytes(&lo), Fr::from_bytes(&hi))
}

#[inline(always)]
fn hash_to_fr(bytes: &[u8]) -> Fr {
    Fr::from_bytes(&hash32(bytes))
}

fn u64_to_be32(x: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&x.to_be_bytes());
    out
}

fn generate_eta_challenge(
    proof: &Proof,
    pub_inputs: &[u8],
    cs: u64,
    pis_total: u64,
    offset: u64,
) -> (RelationParameters, Fr) {
    let mut data = Vec::new();
    data.extend_from_slice(&u64_to_be32(cs));
    data.extend_from_slice(&u64_to_be32(pis_total));
    data.extend_from_slice(&u64_to_be32(offset));
    let mut chunks = pub_inputs.chunks_exact(32);
    for pi in &mut chunks {
        data.extend_from_slice(pi);
    }
    debug_assert!(chunks.remainder().is_empty());
    // Append pairing point object (16 Fr) after public inputs
    for fr in &proof.pairing_point_object {
        data.extend_from_slice(&fr.to_bytes());
    }
    for w in &[&proof.w1, &proof.w2, &proof.w3] {
        push_point(&mut data, &w.to_affine());
    }

    let h = hash_to_fr(&data);
    let (eta, eta_two) = split_challenge(h);
    let h2 = hash_to_fr(&h.to_bytes());
    let (eta_three, _) = split_challenge(h2);

    (
        RelationParameters {
            eta,
            eta_two,
            eta_three,
            beta: Fr::zero(),
            gamma: Fr::zero(),
            public_inputs_delta: Fr::zero(),
        },
        h2,
    )
}

fn generate_beta_and_gamma_challenges(prev: Fr, proof: &Proof) -> (Fr, Fr, Fr) {
    let mut data = prev.to_bytes().to_vec();
    for w in &[
        &proof.lookup_read_counts,
        &proof.lookup_read_tags,
        &proof.w4,
    ] {
        push_point(&mut data, &w.to_affine());
    }
    let h = hash_to_fr(&data);
    let (beta, gamma) = split_challenge(h);
    (beta, gamma, h)
}

fn generate_alpha_challenges(prev: Fr, proof: &Proof) -> (Vec<Fr>, Fr) {
    let mut data = prev.to_bytes().to_vec();
    for w in &[&proof.lookup_inverses, &proof.z_perm] {
        push_point(&mut data, &w.to_affine());
    }
    let mut cur = hash_to_fr(&data);

    let mut alphas = Vec::with_capacity(25);
    let (a0, a1) = split_challenge(cur);
    alphas.push(a0);
    alphas.push(a1);

    while alphas.len() < 25 {
        cur = hash_to_fr(&cur.to_bytes());
        let (lo, hi) = split_challenge(cur);
        alphas.push(lo);
        if alphas.len() < 25 {
            alphas.push(hi);
        }
    }
    (alphas, cur)
}

fn generate_challenges(mut cur: Fr, rounds: usize) -> (Vec<Fr>, Fr) {
    let mut out = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        cur = hash_to_fr(&cur.to_bytes());
        out.push(split_challenge(cur).0);
    }
    (out, cur)
}

fn generate_relation_parameters_challenges(
    proof: &Proof,
    pub_inputs: &[u8],
    cs: u64,
    pis_total: u64,
    offset: u64,
) -> (RelationParameters, Fr) {
    let (mut rp, prev) = generate_eta_challenge(proof, pub_inputs, cs, pis_total, offset);
    let (beta, gamma, next) = generate_beta_and_gamma_challenges(prev, proof);
    rp.beta = beta;
    rp.gamma = gamma;
    (rp, next)
}

fn generate_gate_challenges(prev: Fr) -> (Vec<Fr>, Fr) {
    generate_challenges(prev, CONST_PROOF_SIZE_LOG_N)
}

fn generate_sumcheck_challenges(proof: &Proof, prev: Fr) -> (Vec<Fr>, Fr) {
    let mut cur = prev;
    let mut out = Vec::with_capacity(CONST_PROOF_SIZE_LOG_N);
    for r in 0..CONST_PROOF_SIZE_LOG_N {
        let mut data = cur.to_bytes().to_vec();
        for &c in &proof.sumcheck_univariates[r] {
            data.extend_from_slice(&c.to_bytes());
        }
        cur = hash_to_fr(&data);
        out.push(split_challenge(cur).0);
    }
    (out, cur)
}

fn generate_rho_challenge(proof: &Proof, prev: Fr) -> (Fr, Fr) {
    let mut data = prev.to_bytes().to_vec();
    for &e in &proof.sumcheck_evaluations {
        data.extend_from_slice(&e.to_bytes());
    }
    let rho = split_challenge(hash_to_fr(&data)).0;
    let next = hash_to_fr(&data);
    (rho, next)
}

fn generate_gemini_r_challenge(proof: &Proof, prev: Fr) -> (Fr, Fr) {
    let mut data = prev.to_bytes().to_vec();
    for pt in &proof.gemini_fold_comms {
        push_point(&mut data, &pt.to_affine());
    }
    let gemini_r = split_challenge(hash_to_fr(&data)).0;
    let next = hash_to_fr(&data);
    (gemini_r, next)
}

fn generate_shplonk_nu_challenge(proof: &Proof, prev: Fr) -> (Fr, Fr) {
    let mut data = prev.to_bytes().to_vec();
    for &a in &proof.gemini_a_evaluations {
        data.extend_from_slice(&a.to_bytes());
    }
    let shplonk_nu = split_challenge(hash_to_fr(&data)).0;
    let next = hash_to_fr(&data);
    (shplonk_nu, next)
}

fn generate_shplonk_z_challenge(proof: &Proof, prev: Fr) -> (Fr, Fr) {
    let mut data = prev.to_bytes().to_vec();
    push_point(&mut data, &proof.shplonk_q.to_affine());
    let shplonk_z = split_challenge(hash_to_fr(&data)).0;
    let next = hash_to_fr(&data);
    (shplonk_z, next)
}

pub fn generate_transcript(
    proof: &Proof,
    pub_inputs: &[u8],
    cs: u64,
    pis_total: u64,
    offset: u64,
) -> Transcript {
    // 1) eta/beta/gamma
    let (rp, cur) =
        generate_relation_parameters_challenges(proof, pub_inputs, cs, pis_total, offset);

    // 2) alphas
    let (alphas, cur) = generate_alpha_challenges(cur, proof);

    // 3) gate challenges
    let (gate_chals, cur) = generate_gate_challenges(cur);

    // 4) sumcheck challenges
    let (u_chals, cur) = generate_sumcheck_challenges(proof, cur);

    // 5) rho
    let (rho, cur) = generate_rho_challenge(proof, cur);

    // 6) gemini_r
    let (gemini_r, cur) = generate_gemini_r_challenge(proof, cur);

    // 7) shplonk_nu
    let (shplonk_nu, cur) = generate_shplonk_nu_challenge(proof, cur);

    // 8) shplonk_z
    let (shplonk_z, _cur) = generate_shplonk_z_challenge(proof, cur);

    trace!("===== TRANSCRIPT PARAMETERS =====");
    trace!("eta = 0x{}", hex::encode(rp.eta.to_bytes()));
    trace!("eta_two = 0x{}", hex::encode(rp.eta_two.to_bytes()));
    trace!("eta_three = 0x{}", hex::encode(rp.eta_three.to_bytes()));
    trace!("beta = 0x{}", hex::encode(rp.beta.to_bytes()));
    trace!("gamma = 0x{}", hex::encode(rp.gamma.to_bytes()));
    trace!("rho = 0x{}", hex::encode(rho.to_bytes()));
    trace!("gemini_r = 0x{}", hex::encode(gemini_r.to_bytes()));
    trace!("shplonk_nu = 0x{}", hex::encode(shplonk_nu.to_bytes()));
    trace!("shplonk_z = 0x{}", hex::encode(shplonk_z.to_bytes()));
    trace!("circuit_size = {}", cs);
    trace!("public_inputs_total = {}", pis_total);
    trace!("public_inputs_offset = {}", offset);
    trace!("=================================");

    Transcript {
        rel_params: rp,
        alphas,
        gate_challenges: gate_chals,
        sumcheck_u_challenges: u_chals,
        rho,
        gemini_r,
        shplonk_nu,
        shplonk_z,
    }
}

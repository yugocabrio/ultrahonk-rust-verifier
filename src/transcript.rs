// srctranscript.rs
//! Fiat–Shamir transcript for UltraHonk

use crate::debug::{dbg_fr, dbg_vec};
use crate::trace;
use crate::{
    field::Fr,
    hash::keccak256,
    types::{Proof, RelationParameters, Transcript, CONST_PROOF_SIZE_LOG_N},
    utils::fq_to_halves_be,
};
use ark_bn254::G1Affine;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

fn push_point(buf: &mut Vec<u8>, pt: &G1Affine) {
    let (x_lo, x_hi) = fq_to_halves_be(&pt.x);
    let (y_lo, y_hi) = fq_to_halves_be(&pt.y);
    buf.extend_from_slice(&x_lo);
    buf.extend_from_slice(&x_hi);
    buf.extend_from_slice(&y_lo);
    buf.extend_from_slice(&y_hi);
}

fn split(fr: Fr) -> (Fr, Fr) {
    let b = fr.to_bytes();
    let mut lo = [0u8; 32];
    lo[16..].copy_from_slice(&b[16..]);
    let mut hi = [0u8; 32];
    hi[16..].copy_from_slice(&b[..16]);
    (Fr::from_bytes(&lo), Fr::from_bytes(&hi))
}

#[inline(always)]
fn hash_to_fr(bytes: &[u8]) -> Fr {
    Fr::from_bytes(&keccak256(bytes))
}

fn u64_to_be32(x: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&x.to_be_bytes());
    out
}

fn gen_eta(
    proof: &Proof,
    pub_inputs: &[Vec<u8>],
    cs: u64,
    pis: u64,
    offset: u64,
) -> (RelationParameters, Fr) {
    let mut data = Vec::new();
    data.extend_from_slice(&u64_to_be32(cs));
    data.extend_from_slice(&u64_to_be32(pis));
    data.extend_from_slice(&u64_to_be32(offset));
    for pi in pub_inputs {
        data.extend_from_slice(pi);
    }
    for w in &[&proof.w1, &proof.w2, &proof.w3] {
        push_point(&mut data, &w.to_affine());
    }

    let h = hash_to_fr(&data);
    let (eta, eta_two) = split(h);
    let h2 = hash_to_fr(&h.to_bytes());
    let (eta_three, _) = split(h2);

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

fn gen_beta_gamma(prev: Fr, proof: &Proof) -> (Fr, Fr, Fr) {
    let mut data = prev.to_bytes().to_vec();
    for w in &[
        &proof.lookup_read_counts,
        &proof.lookup_read_tags,
        &proof.w4,
    ] {
        push_point(&mut data, &w.to_affine());
    }
    let h = hash_to_fr(&data);
    let (beta, gamma) = split(h);
    (beta, gamma, h)
}

fn gen_alphas(prev: Fr, proof: &Proof) -> (Vec<Fr>, Fr) {
    let mut data = prev.to_bytes().to_vec();
    for w in &[&proof.lookup_inverses, &proof.z_perm] {
        push_point(&mut data, &w.to_affine());
    }
    let mut cur = hash_to_fr(&data);

    let mut alphas = Vec::with_capacity(25);
    let (a0, a1) = split(cur);
    alphas.push(a0);
    alphas.push(a1);

    while alphas.len() < 25 {
        cur = hash_to_fr(&cur.to_bytes());
        let (lo, hi) = split(cur);
        alphas.push(lo);
        if alphas.len() < 25 {
            alphas.push(hi);
        }
    }
    (alphas, cur)
}

fn gen_challenges(mut cur: Fr, rounds: usize) -> (Vec<Fr>, Fr) {
    let mut out = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        cur = hash_to_fr(&cur.to_bytes());
        out.push(split(cur).0);
    }
    (out, cur)
}

pub fn generate_transcript(
    proof: &Proof,
    pub_inputs: &[Vec<u8>],
    cs: u64,
    pis: u64,
    offset: u64,
) -> Transcript {
    // 1) η
    let (mut rp, mut cur) = gen_eta(proof, pub_inputs, cs, pis, offset);

    // 2) β, γ
    let (beta, gamma, tmp) = gen_beta_gamma(cur, proof);
    rp.beta = beta;
    rp.gamma = gamma;
    cur = tmp;

    // 3) α’s
    let (alphas, tmp) = gen_alphas(cur, proof);
    cur = tmp;

    // 4) gate challenges
    let (gate_chals, tmp) = gen_challenges(cur, CONST_PROOF_SIZE_LOG_N);
    cur = tmp;

    // 5) sumcheck u challenges
    let (u_chals, tmp) = {
        let mut t = cur;
        let mut vs = Vec::with_capacity(CONST_PROOF_SIZE_LOG_N);
        for r in 0..CONST_PROOF_SIZE_LOG_N {
            let mut d = t.to_bytes().to_vec();
            for &c in &proof.sumcheck_univariates[r] {
                d.extend_from_slice(&c.to_bytes());
            }
            t = hash_to_fr(&d);
            vs.push(split(t).0);
        }
        (vs, t)
    };
    cur = tmp;

    // 6) ρ
    let mut data = cur.to_bytes().to_vec();
    for &e in &proof.sumcheck_evaluations {
        data.extend_from_slice(&e.to_bytes());
    }
    let rho = split(hash_to_fr(&data)).0;
    cur = hash_to_fr(&data);

    // 7) gemini_r
    let mut data = cur.to_bytes().to_vec();
    for pt in &proof.gemini_fold_comms {
        push_point(&mut data, &pt.to_affine());
    }
    let gemini_r = split(hash_to_fr(&data)).0;
    cur = hash_to_fr(&data);

    // 8) shplonk_nu
    let mut data = cur.to_bytes().to_vec();
    for &a in &proof.gemini_a_evaluations {
        data.extend_from_slice(&a.to_bytes());
    }
    let shplonk_nu = split(hash_to_fr(&data)).0;
    cur = hash_to_fr(&data);

    // 9) shplonk_z
    let mut data = cur.to_bytes().to_vec();
    push_point(&mut data, &proof.shplonk_q.to_affine());
    let shplonk_z = split(hash_to_fr(&data)).0;

    trace!("===== TRANSCRIPT (Rust) =====");
    dbg_fr("eta", &rp.eta);
    dbg_fr("eta_two", &rp.eta_two);
    dbg_fr("eta_three", &rp.eta_three);
    dbg_fr("beta", &rp.beta);
    dbg_fr("gamma", &rp.gamma);
    dbg_vec("alpha", &alphas);
    dbg_vec("gate_ch", &gate_chals);
    dbg_vec("u_ch", &u_chals);
    dbg_fr("rho", &rho);
    dbg_fr("gemini_r", &gemini_r);
    dbg_fr("shplonk_nu", &shplonk_nu);
    dbg_fr("shplonk_z", &shplonk_z);
    trace!("=============================");

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

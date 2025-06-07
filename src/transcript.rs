//! Fiat–Shamir transcript for UltraHonk

use crate::crypto::keccak256;
use crate::field::Fr;
use crate::types::{Proof, Transcript, RelationParameters};
use ark_serialize::CanonicalSerialize;

/// Split a 256-bit Fr into two 128-bit challenges.
fn split(fr: Fr) -> (Fr, Fr) {
    let b = fr.to_bytes();
    let mut lo = [0u8; 32];
    lo[16..].copy_from_slice(&b[16..]);
    let mut hi = [0u8; 32];
    hi[16..].copy_from_slice(&b[..16]);
    (Fr::from_bytes(&lo), Fr::from_bytes(&hi))
}

/// Hash arbitrary bytes into an Fr.
fn hash_to_fr(bytes: &[u8]) -> Fr {
    Fr::from_bytes(&keccak256(bytes))
}

/// Generate η-challenges.
fn gen_eta(
    proof: &Proof,
    pub_inputs: &[Vec<u8>],
    cs: u64,
    pis: u64,
    offset: u64,
) -> (RelationParameters, Fr) {
    let mut data = Vec::new();
    data.extend_from_slice(&cs.to_be_bytes());
    data.extend_from_slice(&pis.to_be_bytes());
    data.extend_from_slice(&offset.to_be_bytes());
    for pi in pub_inputs { data.extend_from_slice(pi); }
    for w in &[&proof.w1, &proof.w2, &proof.w3] {
        let pt = w.to_affine();
        let mut x_bytes = Vec::new();
        let mut y_bytes = Vec::new();
        pt.x.serialize_compressed(&mut x_bytes).unwrap();
        pt.y.serialize_compressed(&mut y_bytes).unwrap();
        data.extend_from_slice(&x_bytes);
        data.extend_from_slice(&y_bytes);
    }
    let h = hash_to_fr(&data);
    let (eta, eta_two) = split(h);
    let h2 = hash_to_fr(&h.to_bytes());
    let (eta_three, _) = split(h2);
    (RelationParameters {
        eta, eta_two, eta_three,
        beta: Fr::zero(),
        gamma: Fr::zero(),
        public_inputs_delta: Fr::zero(),
    }, h2)
}

/// Generate β, γ.
fn gen_beta_gamma(prev: Fr, proof: &Proof) -> (Fr, Fr, Fr) {
    let mut data = prev.to_bytes().to_vec();
    for w in &[&proof.lookup_read_counts, &proof.lookup_read_tags, &proof.w4] {
        let pt = w.to_affine();
        let mut x_bytes = Vec::new();
        let mut y_bytes = Vec::new();
        pt.x.serialize_compressed(&mut x_bytes).unwrap();
        pt.y.serialize_compressed(&mut y_bytes).unwrap();
        data.extend_from_slice(&x_bytes);
        data.extend_from_slice(&y_bytes);
    }
    let h = hash_to_fr(&data);
    let (beta, gamma) = split(h);
    (beta, gamma, h)
}

/// Generate α's.
fn gen_alphas(prev: Fr) -> (Vec<Fr>, Fr) {
    let mut alphas = Vec::with_capacity(25);
    let mut cur = prev;
    for _ in 0..12 {
        let (a_lo, a_hi) = split(cur);
        alphas.push(a_lo);
        alphas.push(a_hi);
        cur = hash_to_fr(&cur.to_bytes());
    }
    if alphas.len() < 25 {
        let (last, _) = split(cur);
        alphas.push(last);
    }
    (alphas, cur)
}

/// Generate vector of challenges by hashing sequentially.
fn gen_challenges(prev: Fr, rounds: usize) -> (Vec<Fr>, Fr) {
    let mut v = Vec::with_capacity(rounds);
    let mut cur = prev;
    for _ in 0..rounds {
        cur = hash_to_fr(&cur.to_bytes());
        let (r, _) = split(cur);
        v.push(r);
    }
    (v, cur)
}

/// Generate transcript fully.
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
    let (b, g, cur2) = gen_beta_gamma(cur, proof);
    rp.beta = b; rp.gamma = g; cur = cur2;
    // 3) α's
    let (alphas, cur3) = gen_alphas(cur);
    cur = cur3;
    // 4) gate challenges
    let log_n = (cs as f64).log2() as usize;
    let (gates, cur4) = gen_challenges(cur, log_n);
    cur = cur4;
    // 5) sumcheck u's
    let (us, cur5) = {
        let mut tmp = cur;
        let mut vs = Vec::with_capacity(log_n);
        for r in 0..log_n {
            let mut data = tmp.to_bytes().to_vec();
            for &coeff in proof.sumcheck_univariates[r].iter() {
                data.extend_from_slice(&coeff.to_bytes());
            }
            tmp = hash_to_fr(&data);
            let (u, _) = split(tmp);
            vs.push(u);
        }
        (vs, tmp)
    };
    cur = cur5;
    // 6) ρ
    let mut data = cur.to_bytes().to_vec();
    for &e in proof.sumcheck_evaluations.iter() {
        data.extend_from_slice(&e.to_bytes());
    }
    let rho = split(hash_to_fr(&data)).0;
    cur = hash_to_fr(&data);
    // 7) gemini_r
    let mut data = cur.to_bytes().to_vec();
    for pt in proof.gemini_fold_comms.iter() {
        let a = pt.to_affine();
        let mut x_bytes = Vec::new();
        let mut y_bytes = Vec::new();
        a.x.serialize_compressed(&mut x_bytes).unwrap();
        a.y.serialize_compressed(&mut y_bytes).unwrap();
        data.extend_from_slice(&x_bytes);
        data.extend_from_slice(&y_bytes);
    }
    let gemini_r = split(hash_to_fr(&data)).0;
    cur = hash_to_fr(&data);
    // 8) shplonk_nu
    let mut data = cur.to_bytes().to_vec();
    for &a in proof.gemini_a_evaluations.iter() {
        data.extend_from_slice(&a.to_bytes());
    }
    let shplonk_nu = split(hash_to_fr(&data)).0;
    cur = hash_to_fr(&data);
    // 9) shplonk_z
    let mut data = cur.to_bytes().to_vec();
    let a = proof.shplonk_q.to_affine();
    let mut x_bytes = Vec::new();
    let mut y_bytes = Vec::new();
    a.x.serialize_compressed(&mut x_bytes).unwrap();
    a.y.serialize_compressed(&mut y_bytes).unwrap();
    data.extend_from_slice(&x_bytes);
    data.extend_from_slice(&y_bytes);
    let shplonk_z = split(hash_to_fr(&data)).0;

    Transcript {
        rel_params: rp,
        alphas,
        gate_challenges: gates,
        sumcheck_u_challenges: us,
        rho,
        gemini_r,
        shplonk_nu,
        shplonk_z,
    }
}

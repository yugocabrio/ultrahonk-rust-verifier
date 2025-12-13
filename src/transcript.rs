//! Fiat–Shamir transcript for UltraHonk

use crate::trace;
use crate::{
    field::Fr,
    hash::{hash32, HashInput},
    types::{Proof, RelationParameters, Transcript, CONST_PROOF_SIZE_LOG_N},
};
use ark_bn254::G1Affine;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

struct HashBuf {
    bytes: Vec<u8>,
    fields: Vec<Fr>,
}

impl HashBuf {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            fields: Vec::new(),
        }
    }

    fn push_fr(&mut self, fr: &Fr) {
        let arr = fr.to_bytes();
        self.bytes.extend_from_slice(&arr);
        self.fields.push(*fr);
    }

    fn push_u64(&mut self, value: u64) {
        let arr = u64_to_be32(value);
        self.bytes.extend_from_slice(&arr);
        self.fields.push(Fr::from_bytes(&arr));
    }

    fn push_bytes32(&mut self, bytes: &[u8; 32]) {
        self.bytes.extend_from_slice(bytes);
        self.fields.push(Fr::from_bytes(bytes));
    }

    fn push_pub_input(&mut self, bytes: &[u8]) {
        assert!(bytes.len() % 32 == 0);
        for chunk in bytes.chunks(32) {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(chunk);
            self.push_bytes32(&arr);
        }
    }

    fn push_point(&mut self, pt: &G1Affine) {
        use crate::utils::fq_to_halves_be;
        let (x_lo, x_hi) = fq_to_halves_be(&pt.x);
        let (y_lo, y_hi) = fq_to_halves_be(&pt.y);
        for limb in [x_lo, x_hi, y_lo, y_hi] {
            self.push_bytes32(&limb);
        }
    }
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
fn hash_to_fr(buf: &HashBuf) -> Fr {
    Fr::from_bytes(&hash32(&HashInput {
        bytes: &buf.bytes,
        fields: &buf.fields,
    }))
}

fn hash_single(fr: &Fr) -> Fr {
    let mut buf = HashBuf::new();
    buf.push_fr(fr);
    hash_to_fr(&buf)
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
    pis_total: u64,
    offset: u64,
) -> (RelationParameters, Fr) {
    let mut data = HashBuf::new();
    data.push_u64(cs);
    data.push_u64(pis_total);
    data.push_u64(offset);
    for pi in pub_inputs {
        data.push_pub_input(pi);
    }
    // Append pairing point object (16 Fr) after public inputs
    for fr in &proof.pairing_point_object {
        data.push_fr(fr);
    }
    for w in &[&proof.w1, &proof.w2, &proof.w3] {
        data.push_point(&w.to_affine());
    }

    let h = hash_to_fr(&data);
    let (eta, eta_two) = split(h);
    let h2 = hash_single(&h);
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
    let mut data = HashBuf::new();
    data.push_fr(&prev);
    for w in &[
        &proof.lookup_read_counts,
        &proof.lookup_read_tags,
        &proof.w4,
    ] {
        data.push_point(&w.to_affine());
    }
    let h = hash_to_fr(&data);
    let (beta, gamma) = split(h);
    (beta, gamma, h)
}

fn gen_alphas(prev: Fr, proof: &Proof) -> (Vec<Fr>, Fr) {
    let mut data = HashBuf::new();
    data.push_fr(&prev);
    for w in &[&proof.lookup_inverses, &proof.z_perm] {
        data.push_point(&w.to_affine());
    }
    let mut cur = hash_to_fr(&data);

    let mut alphas = Vec::with_capacity(25);
    let (a0, a1) = split(cur);
    alphas.push(a0);
    alphas.push(a1);

    while alphas.len() < 25 {
        cur = hash_single(&cur);
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
        cur = hash_single(&cur);
        out.push(split(cur).0);
    }
    (out, cur)
}

pub fn generate_transcript(
    proof: &Proof,
    pub_inputs: &[Vec<u8>],
    cs: u64,
    pis_total: u64,
    offset: u64,
) -> Transcript {
    // 1) η
    let (mut rp, mut cur) = gen_eta(proof, pub_inputs, cs, pis_total, offset);

    // 2) β, γ
    let (beta, gamma, tmp) = gen_beta_gamma(cur, proof);
    rp.beta = beta;
    rp.gamma = gamma;
    cur = tmp;

    // 3) α’s
    let (alphas, tmp) = gen_alphas(cur, proof);
    cur = tmp;

    // 4) gate challenges (padded to constant proof size)
    let (gate_chals, tmp) = gen_challenges(cur, CONST_PROOF_SIZE_LOG_N);
    cur = tmp;

    // 5) sumcheck challenges - sumcheckUnivariates
    let (u_chals, tmp) = {
        let mut t = cur;
        let mut vs = Vec::with_capacity(CONST_PROOF_SIZE_LOG_N);
        for r in 0..CONST_PROOF_SIZE_LOG_N {
            let mut buf = HashBuf::new();
            buf.push_fr(&t);
            for &c in &proof.sumcheck_univariates[r] {
                buf.push_fr(&c);
            }
            t = hash_to_fr(&buf);
            vs.push(split(t).0);
            cur = t; // update cur at each iteration
        }
        (vs, cur)
    };

    // 6) ρ
    let mut data = HashBuf::new();
    data.push_fr(&cur);
    for &e in &proof.sumcheck_evaluations {
        data.push_fr(&e);
    }
    let hashed = hash_to_fr(&data);
    let rho = split(hashed).0;
    cur = hashed;

    // 7) gemini_r
    let mut data = HashBuf::new();
    data.push_fr(&cur);
    for pt in &proof.gemini_fold_comms {
        data.push_point(&pt.to_affine());
    }
    let hashed = hash_to_fr(&data);
    let gemini_r = split(hashed).0;
    cur = hashed;

    // 8) shplonk_nu
    let mut data = HashBuf::new();
    data.push_fr(&cur);
    for &a in &proof.gemini_a_evaluations {
        data.push_fr(&a);
    }
    let hashed = hash_to_fr(&data);
    let shplonk_nu = split(hashed).0;
    cur = hashed;

    // 9) shplonk_z
    let mut data = HashBuf::new();
    data.push_fr(&cur);
    data.push_point(&proof.shplonk_q.to_affine());
    let shplonk_z = split(hash_to_fr(&data)).0;

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

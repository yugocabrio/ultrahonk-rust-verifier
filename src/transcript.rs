//! Fiat–Shamir transcript for UltraHonk

use crate::trace;
use crate::{
    field::Fr,
    hash::hash32,
    types::{Proof, RelationParameters, Transcript, CONST_PROOF_SIZE_LOG_N, NUMBER_OF_ALPHAS},
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

fn split_challenge(challenge: Fr) -> (Fr, Fr) {
    let challenge_bytes = challenge.to_bytes();
    let mut low_bytes = [0u8; 32];
    low_bytes[16..].copy_from_slice(&challenge_bytes[16..]);
    let mut high_bytes = [0u8; 32];
    high_bytes[16..].copy_from_slice(&challenge_bytes[..16]);
    (Fr::from_bytes(&low_bytes), Fr::from_bytes(&high_bytes))
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
    public_inputs: &[u8],
    circuit_size: u64,
    public_inputs_size: u64,
    pub_inputs_offset: u64,
) -> (Fr, Fr, Fr, Fr) {
    let mut data = Vec::new();
    data.extend_from_slice(&u64_to_be32(circuit_size));
    data.extend_from_slice(&u64_to_be32(public_inputs_size));
    data.extend_from_slice(&u64_to_be32(pub_inputs_offset));
    let mut chunks = public_inputs.chunks_exact(32);
    for pi in &mut chunks {
        data.extend_from_slice(pi);
    }
    debug_assert!(chunks.remainder().is_empty());
    for fr in &proof.pairing_point_object {
        data.extend_from_slice(&fr.to_bytes());
    }
    for w in &[&proof.w1, &proof.w2, &proof.w3] {
        push_point(&mut data, &w.to_affine());
    }

    let previous_challenge = hash_to_fr(&data);
    let (eta, eta_two) = split_challenge(previous_challenge);
    let previous_challenge = hash_to_fr(&previous_challenge.to_bytes());
    let (eta_three, _) = split_challenge(previous_challenge);

    (eta, eta_two, eta_three, previous_challenge)
}

fn generate_beta_and_gamma_challenges(
    previous_challenge: Fr,
    proof: &Proof,
) -> (Fr, Fr, Fr) {
    let mut data = previous_challenge.to_bytes().to_vec();
    for w in &[
        &proof.lookup_read_counts,
        &proof.lookup_read_tags,
        &proof.w4,
    ] {
        push_point(&mut data, &w.to_affine());
    }
    let next_previous_challenge = hash_to_fr(&data);
    let (beta, gamma) = split_challenge(next_previous_challenge);
    (beta, gamma, next_previous_challenge)
}

fn generate_alpha_challenges(
    previous_challenge: Fr,
    proof: &Proof,
) -> ([Fr; NUMBER_OF_ALPHAS], Fr) {
    let mut data = previous_challenge.to_bytes().to_vec();
    for w in &[&proof.lookup_inverses, &proof.z_perm] {
        push_point(&mut data, &w.to_affine());
    }
    let mut next_previous_challenge = hash_to_fr(&data);

    let mut alphas = [Fr::zero(); NUMBER_OF_ALPHAS];
    let (a0, a1) = split_challenge(next_previous_challenge);
    alphas[0] = a0;
    alphas[1] = a1;

    for i in 1..(NUMBER_OF_ALPHAS / 2) {
        next_previous_challenge = hash_to_fr(&next_previous_challenge.to_bytes());
        let (lo, hi) = split_challenge(next_previous_challenge);
        alphas[2 * i] = lo;
        alphas[2 * i + 1] = hi;
    }

    if (NUMBER_OF_ALPHAS & 1) == 1 && NUMBER_OF_ALPHAS > 2 {
        next_previous_challenge = hash_to_fr(&next_previous_challenge.to_bytes());
        let (last, _) = split_challenge(next_previous_challenge);
        alphas[NUMBER_OF_ALPHAS - 1] = last;
    }

    (alphas, next_previous_challenge)
}

fn generate_relation_parameters_challenges(
    proof: &Proof,
    public_inputs: &[u8],
    circuit_size: u64,
    public_inputs_size: u64,
    pub_inputs_offset: u64,
) -> (RelationParameters, Fr) {
    let (eta, eta_two, eta_three, previous_challenge) = generate_eta_challenge(
        proof,
        public_inputs,
        circuit_size,
        public_inputs_size,
        pub_inputs_offset,
    );
    let (beta, gamma, next_previous_challenge) =
        generate_beta_and_gamma_challenges(previous_challenge, proof);
    let rp = RelationParameters {
        eta,
        eta_two,
        eta_three,
        beta,
        gamma,
        public_inputs_delta: Fr::zero(),
    };
    (rp, next_previous_challenge)
}

fn generate_gate_challenges(
    previous_challenge: Fr,
) -> ([Fr; CONST_PROOF_SIZE_LOG_N], Fr) {
    let mut next_previous_challenge = previous_challenge;
    let mut gate_challenges = [Fr::zero(); CONST_PROOF_SIZE_LOG_N];
    for i in 0..CONST_PROOF_SIZE_LOG_N {
        next_previous_challenge = hash_to_fr(&next_previous_challenge.to_bytes());
        gate_challenges[i] = split_challenge(next_previous_challenge).0;
    }
    (gate_challenges, next_previous_challenge)
}

fn generate_sumcheck_challenges(
    proof: &Proof,
    previous_challenge: Fr,
) -> ([Fr; CONST_PROOF_SIZE_LOG_N], Fr) {
    let mut next_previous_challenge = previous_challenge;
    let mut sumcheck_challenges = [Fr::zero(); CONST_PROOF_SIZE_LOG_N];
    for r in 0..CONST_PROOF_SIZE_LOG_N {
        let mut data = next_previous_challenge.to_bytes().to_vec();
        for &c in proof.sumcheck_univariates[r].iter() {
            data.extend_from_slice(&c.to_bytes());
        }
        next_previous_challenge = hash_to_fr(&data);
        sumcheck_challenges[r] = split_challenge(next_previous_challenge).0;
    }
    (sumcheck_challenges, next_previous_challenge)
}

fn generate_rho_challenge(proof: &Proof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut data = previous_challenge.to_bytes().to_vec();
    for &e in proof.sumcheck_evaluations.iter() {
        data.extend_from_slice(&e.to_bytes());
    }
    let next_previous_challenge = hash_to_fr(&data);
    let rho = split_challenge(next_previous_challenge).0;
    (rho, next_previous_challenge)
}

fn generate_gemini_r_challenge(proof: &Proof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut data = previous_challenge.to_bytes().to_vec();
    for pt in proof.gemini_fold_comms.iter() {
        push_point(&mut data, &pt.to_affine());
    }
    let next_previous_challenge = hash_to_fr(&data);
    let gemini_r = split_challenge(next_previous_challenge).0;
    (gemini_r, next_previous_challenge)
}

fn generate_shplonk_nu_challenge(proof: &Proof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut data = previous_challenge.to_bytes().to_vec();
    for &a in proof.gemini_a_evaluations.iter() {
        data.extend_from_slice(&a.to_bytes());
    }
    let next_previous_challenge = hash_to_fr(&data);
    let shplonk_nu = split_challenge(next_previous_challenge).0;
    (shplonk_nu, next_previous_challenge)
}

fn generate_shplonk_z_challenge(proof: &Proof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut data = previous_challenge.to_bytes().to_vec();
    push_point(&mut data, &proof.shplonk_q.to_affine());
    let next_previous_challenge = hash_to_fr(&data);
    let shplonk_z = split_challenge(next_previous_challenge).0;
    (shplonk_z, next_previous_challenge)
}

pub fn generate_transcript(
    proof: &Proof,
    public_inputs: &[u8],
    circuit_size: u64,
    public_inputs_size: u64,
    pub_inputs_offset: u64,
) -> Transcript {
    // 1) eta/beta/gamma
    let (rp, previous_challenge) = generate_relation_parameters_challenges(
        proof,
        public_inputs,
        circuit_size,
        public_inputs_size,
        pub_inputs_offset,
    );

    // 2) alphas
    let (alphas, previous_challenge) = generate_alpha_challenges(previous_challenge, proof);

    // 3) gate challenges
    let (gate_chals, previous_challenge) = generate_gate_challenges(previous_challenge);

    // 4) sumcheck challenges
    let (u_chals, previous_challenge) = generate_sumcheck_challenges(proof, previous_challenge);

    // 5) rho
    let (rho, previous_challenge) = generate_rho_challenge(proof, previous_challenge);

    // 6) gemini_r
    let (gemini_r, previous_challenge) = generate_gemini_r_challenge(proof, previous_challenge);

    // 7) shplonk_nu
    let (shplonk_nu, previous_challenge) = generate_shplonk_nu_challenge(proof, previous_challenge);

    // 8) shplonk_z
    let (shplonk_z, _previous_challenge) = generate_shplonk_z_challenge(proof, previous_challenge);

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
    trace!("circuit_size = {}", circuit_size);
    trace!("public_inputs_total = {}", public_inputs_size);
    trace!("public_inputs_offset = {}", pub_inputs_offset);
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

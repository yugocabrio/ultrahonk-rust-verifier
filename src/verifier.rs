//! UltraHonk verifier

use crate::{
    field::Fr,
    shplemini::verify_shplemini,
    sumcheck::verify_sumcheck,
    transcript::generate_transcript,
    types::PAIRING_POINTS_SIZE,
    utils::{load_proof, load_vk_from_bytes},
};
use soroban_sdk::{Bytes, Env};

/// Error type describing the specific reason verification failed.
#[derive(Debug)]
pub enum VerifyError {
    InvalidInput(&'static str),
    SumcheckFailed(&'static str),
    ShplonkFailed(&'static str),
}

pub struct UltraHonkVerifier {
    env: Env,
    vk: crate::types::VerificationKey,
}

impl UltraHonkVerifier {
    pub fn new_with_vk(env: &Env, vk: crate::types::VerificationKey) -> Self {
        Self {
            env: env.clone(),
            vk,
        }
    }

    pub fn new(env: &Env, vk_bytes: &Bytes) -> Result<Self, VerifyError> {
        load_vk_from_bytes(vk_bytes)
            .map(|vk| Self::new_with_vk(env, vk))
            .ok_or(VerifyError::InvalidInput("vk parse error"))
    }

    /// Expose a reference to the parsed VK for debugging/inspection.
    pub fn get_vk(&self) -> &crate::types::VerificationKey {
        &self.vk
    }

    /// Top-level verify
    pub fn verify(
        &self,
        proof_bytes: &Bytes,
        public_inputs_bytes: &Bytes,
    ) -> Result<(), VerifyError> {
        // 1) parse proof
        let proof = load_proof(proof_bytes);

        // 2) sanity on public inputs (length and VK metadata if present)
        if public_inputs_bytes.len() % 32 != 0 {
            return Err(VerifyError::InvalidInput(
                "public inputs must be 32-byte aligned",
            ));
        }
        let provided = (public_inputs_bytes.len() / 32) as u64;
        let expected = self
            .vk
            .public_inputs_size
            .checked_sub(PAIRING_POINTS_SIZE as u64)
            .ok_or(VerifyError::InvalidInput("vk inputs < 16"))?;
        if expected != provided {
            return Err(VerifyError::InvalidInput("public inputs mismatch"));
        }

        // 3) Fiat–Shamir transcript
        let pis_total = provided + PAIRING_POINTS_SIZE as u64;
        let pub_inputs_offset = 1;
        let mut t = generate_transcript(
            &self.env,
            &proof,
            public_inputs_bytes,
            self.vk.circuit_size,
            pis_total,
            pub_inputs_offset,
        );

        // 4) Public delta
        t.rel_params.public_inputs_delta = Self::compute_public_input_delta(
            public_inputs_bytes,
            &proof.pairing_point_object,
            t.rel_params.beta,
            t.rel_params.gamma,
            pub_inputs_offset,
            self.vk.circuit_size,
        )
        .map_err(VerifyError::InvalidInput)?;

        // 5) Sum-check
        verify_sumcheck(&proof, &t, &self.vk).map_err(VerifyError::SumcheckFailed)?;

        // 6) Shplonk
        verify_shplemini(&self.env, &proof, &self.vk, &t).map_err(VerifyError::ShplonkFailed)?;

        Ok(())
    }

    fn compute_public_input_delta(
        public_inputs: &Bytes,
        pairing_point_object: &[Fr],
        beta: Fr,
        gamma: Fr,
        offset: u64,
        n: u64,
    ) -> Result<Fr, &'static str> {
        let mut numerator = Fr::one();
        let mut denominator = Fr::one();

        let mut numerator_acc = gamma + beta * Fr::from_u64(n + offset);
        let mut denominator_acc = gamma - beta * Fr::from_u64(offset + 1);

        let mut idx = 0u32;
        while idx < public_inputs.len() {
            let mut arr = [0u8; 32];
            public_inputs.slice(idx..idx + 32).copy_into_slice(&mut arr);
            let public_input = Fr::from_bytes(&arr);
            numerator = numerator * (numerator_acc + public_input);
            denominator = denominator * (denominator_acc + public_input);
            numerator_acc = numerator_acc + beta;
            denominator_acc = denominator_acc - beta;
            idx += 32;
        }
        for public_input in pairing_point_object {
            numerator = numerator * (numerator_acc + *public_input);
            denominator = denominator * (denominator_acc + *public_input);
            numerator_acc = numerator_acc + beta;
            denominator_acc = denominator_acc - beta;
        }
        let denominator_inv = denominator
            .inverse()
            .ok_or("public input delta denom is zero")?;
        Ok(numerator * denominator_inv)
    }
}

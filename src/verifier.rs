//! UltraHonk verifier

use crate::{
    field::Fr,
    shplemini::verify_shplemini,
    sumcheck::verify_sumcheck,
    transcript::generate_transcript,
    utils::{load_proof, load_vk_from_bytes},
};

#[cfg(not(feature = "std"))]
use alloc::{format, string::String};

/// Error type describing the specific reason verification failed.
#[derive(Debug)]
pub enum VerifyError {
    InvalidInput(String),
    SumcheckFailed(String),
    ShplonkFailed(String),
}

/// Allow converting VerifyError into a String for debugging and logging.
impl From<VerifyError> for String {
    fn from(err: VerifyError) -> String {
        match err {
            VerifyError::InvalidInput(s) => format!("Invalid input: {}", s),
            VerifyError::SumcheckFailed(s) => format!("Sum-check failed: {}", s),
            VerifyError::ShplonkFailed(s) => format!("Shplonk failed: {}", s),
        }
    }
}

pub struct UltraHonkVerifier {
    vk: crate::types::VerificationKey,
}

impl UltraHonkVerifier {
    pub fn new_with_vk(vk: crate::types::VerificationKey) -> Self {
        Self { vk }
    }

    pub fn new_from_bytes(vk_bytes: &[u8]) -> Self {
        Self {
            vk: load_vk_from_bytes(vk_bytes),
        }
    }

    /// Expose a reference to the parsed VK for debugging/inspection.
    pub fn get_vk(&self) -> &crate::types::VerificationKey {
        &self.vk
    }

    /// Top-level verify
    pub fn verify(
        &self,
        proof_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Result<(), VerifyError> {
        // 1) parse proof
        let proof = load_proof(proof_bytes);

        // 2) sanity on public inputs (length and VK metadata if present)
        if public_inputs_bytes.len() % 32 != 0 {
            return Err(VerifyError::InvalidInput(
                "public inputs must be 32-byte aligned".into(),
            ));
        }
        let provided = (public_inputs_bytes.len() / 32) as u64;
        let expected = self
            .vk
            .public_inputs_size
            .checked_sub(16)
            .ok_or_else(|| VerifyError::InvalidInput("vk inputs < 16".into()))?;
        if expected != provided {
            return Err(VerifyError::InvalidInput("public inputs mismatch".into()));
        }

        // 3) Fiat–Shamir transcript
        // In bb v0.87.0, publicInputsSize includes pairing point object (16 elements)
        let pis_total = provided + 16;
        let pub_offset = 1;
        let mut tx = generate_transcript(
            &proof,
            public_inputs_bytes,
            self.vk.circuit_size,
            pis_total,
            pub_offset, // pubInputsOffset
        );

        // 4) compute Δₚᵢ and inject
        tx.rel_params.public_inputs_delta = Self::public_inputs_delta(
            public_inputs_bytes,
            &proof.pairing_point_object,
            tx.rel_params.beta,
            tx.rel_params.gamma,
            pub_offset,
            self.vk.circuit_size,
        )
        .map_err(VerifyError::InvalidInput)?;

        // 5) Sum-check: returns SumcheckFailed when this step fails.
        verify_sumcheck(&proof, &tx, &self.vk).map_err(VerifyError::SumcheckFailed)?;

        // 6) Shplonk (batch opening): returns ShplonkFailed when this stage fails.
        verify_shplemini(&proof, &self.vk, &tx).map_err(VerifyError::ShplonkFailed)?;

        Ok(())
    }

    fn public_inputs_delta(
        public_inputs: &[u8],
        pairing_point_object: &[Fr],
        beta: Fr,
        gamma: Fr,
        offset: u64,
        n: u64,
    ) -> Result<Fr, String> {
        let mut num = Fr::one();
        let mut den = Fr::one();

        let mut num_acc = gamma + beta * Fr::from_u64(n + offset);
        let mut den_acc = gamma - beta * Fr::from_u64(offset + 1);

        let mut chunks = public_inputs.chunks_exact(32);
        for bytes in &mut chunks {
            let pi = Fr::from_bytes(bytes.try_into().unwrap());
            num = num * (num_acc + pi);
            den = den * (den_acc + pi);
            num_acc = num_acc + beta;
            den_acc = den_acc - beta;
        }
        debug_assert!(chunks.remainder().is_empty());
        for pi in pairing_point_object {
            num = num * (num_acc + *pi);
            den = den * (den_acc + *pi);
            num_acc = num_acc + beta;
            den_acc = den_acc - beta;
        }
        let den_inv = den
            .inverse()
            .ok_or_else(|| String::from("public inputs delta denominator is zero"))?;
        Ok(num * den_inv)
    }
}

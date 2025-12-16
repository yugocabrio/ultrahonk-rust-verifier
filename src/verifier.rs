//! UltraHonk verifier

use crate::{
    field::Fr, shplemini::verify_shplemini, sumcheck::verify_sumcheck,
    transcript::generate_transcript, utils::load_proof,
};

#[cfg(feature = "serde_json")]
use crate::utils::load_vk_from_json;

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};
// ===============================================

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

    #[cfg(feature = "serde_json")]
    pub fn new_from_json(json_data: &str) -> Self {
        Self {
            vk: load_vk_from_json(json_data),
        }
    }

    /// Expose a reference to the parsed VK for debugging/inspection.
    pub fn get_vk(&self) -> &crate::types::VerificationKey {
        &self.vk
    }

    /// Top-level verify; return type changed from String to the concrete VerifyError.
    pub fn verify(
        &self,
        proof_bytes: &[u8],
        public_inputs_bytes: &[Vec<u8>],
    ) -> Result<(), VerifyError> {
        // 1) parse proof
        let proof = load_proof(proof_bytes);

        // 2) sanity on public inputs (length and VK metadata if present)
        if public_inputs_bytes
            .iter()
            .any(|pi| pi.len() != 32)
        {
            return Err(VerifyError::InvalidInput(
                "public inputs must be 32 bytes each".into(),
            ));
        }
        if self.vk.public_inputs_size != 0 {
            let expected = self.vk.public_inputs_size.saturating_sub(16);
            let provided = public_inputs_bytes.len() as u64;
            if expected != provided {
                return Err(VerifyError::InvalidInput(format!(
                    "public inputs count mismatch (vk: {}, provided: {})",
                    expected, provided
                )));
            }
        }

        // 3) Fiat–Shamir transcript
        // In bb v0.87.0, publicInputsSize includes pairing point object (16 elements)
        let pis_total = public_inputs_bytes.len() as u64 + 16;
        let pub_offset = if self.vk.pub_inputs_offset != 0 {
            self.vk.pub_inputs_offset
        } else {
            1
        };
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
        public_inputs: &[Vec<u8>],
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

        for bytes in public_inputs {
            let pi = Fr::from_bytes(bytes.as_slice().try_into().unwrap());
            num = num * (num_acc + pi);
            den = den * (den_acc + pi);
            num_acc = num_acc + beta;
            den_acc = den_acc - beta;
        }
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

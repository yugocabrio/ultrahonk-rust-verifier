//! The main UltraHonk verifier

use crate::transcript::generate_transcript;
use crate::{utils::{load_proof, load_vk}, sumcheck::verify_sumcheck, shplonk::verify_shplonk};
use crate::types::VerificationKey;
use crate::field::Fr;

/// High‐level verifier struct.
pub struct HonkVerifier {
    vk: VerificationKey,
}

impl HonkVerifier {
    /// Create from a VK JSON file.
    pub fn new(vk_path: &str) -> Self {
        let vk = load_vk(vk_path);
        HonkVerifier { vk }
    }

    /// Verify a proof and public inputs.
    pub fn verify(
        &self,
        proof_bytes: &[u8],
        public_inputs: &[Vec<u8>],
    ) -> Result<(), String> {
        // 1) load and parse proof
        let proof = load_proof(proof_bytes);

        // 2) check pub-inputs size
        if public_inputs.len() != self.vk.public_inputs_size as usize {
            return Err(format!(
                "Expected {} public inputs, got {}",
                self.vk.public_inputs_size,
                public_inputs.len()
            ));
        }

        // 3) generate transcript
        let mut tx = generate_transcript(
            &proof,
            public_inputs,
            self.vk.circuit_size,
            self.vk.public_inputs_size,
            1, // offset
        );

        // 4) compute public_inputs_delta and inject
        tx.rel_params.public_inputs_delta =
            self.compute_public_inputs_delta(
                public_inputs,
                tx.rel_params.beta,
                tx.rel_params.gamma,
                1,
                self.vk.circuit_size,
            );

        // 5) sumcheck
        verify_sumcheck(&proof, &tx, &self.vk)?;

        // 6) shplonk
        verify_shplonk(&proof, &self.vk, &tx)?;

        Ok(())
    }

    /// Compute public_inputs_delta exactly as TS's helper.
    fn compute_public_inputs_delta(
        &self,
        public_inputs: &[Vec<u8>],
        beta: Fr,
        gamma: Fr,
        offset: u64,
        circuit_size: u64,
    ) -> Fr {
        let mut num = Fr::one();
        let mut den = Fr::one();

        let mut num_acc = gamma + beta * Fr::from_u64(circuit_size + offset);
        let mut den_acc = gamma - beta * Fr::from_u64(offset + 1);

        for pi_bytes in public_inputs {
            let pi = Fr::from_bytes(
                &pi_bytes
                    .as_slice()
                    .try_into()
                    .expect("Each public input must be 32 bytes"),
            );
            num = num * (num_acc + pi);
            den = den * (den_acc + pi);
            num_acc = num_acc + beta;
            den_acc = den_acc - beta;
        }

        num.div(&den)
    }
}

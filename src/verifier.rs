//! UltraHonk verifier

use crate::{
    field::Fr,
    shplemini::verify_shplemini,
    sumcheck::verify_sumcheck,
    transcript::generate_transcript,
    utils::{load_proof, load_vk},
};

pub struct UltraHonkVerifier {
    vk: crate::types::VerificationKey,
}

impl UltraHonkVerifier {
    pub fn new(vk_path: &str) -> Self {
        Self {
            vk: load_vk(vk_path),
        }
    }

    /// Top-level verify
    pub fn verify(
        &self,
        proof_bytes: &[u8],
        public_inputs_bytes: &[Vec<u8>],
    ) -> Result<(), String> {
        // 1) parse proof
        let proof = load_proof(proof_bytes);

        // 2) sanity on public inputs
        if public_inputs_bytes.len() != self.vk.public_inputs_size as usize {
            return Err(format!(
                "expected {} public inputs, got {}",
                self.vk.public_inputs_size,
                public_inputs_bytes.len()
            ));
        }

        // 3) Fiat–Shamir transcript
        let mut tx = generate_transcript(
            &proof,
            public_inputs_bytes,
            self.vk.circuit_size,
            self.vk.public_inputs_size,
            1, // pubInputsOffset
        );

        // 4) compute Δₚᵢ and inject ( **← BUG FIX HERE** )
        tx.rel_params.public_inputs_delta = Self::public_inputs_delta(
            public_inputs_bytes,
            tx.rel_params.beta,
            tx.rel_params.gamma,
            1,
            self.vk.circuit_size,
        );

        // 5) Sum-check
        verify_sumcheck(&proof, &tx, &self.vk)?;

        // 6) Shplonk (batch opening)
        verify_shplemini(&proof, &self.vk, &tx)?;

        Ok(())
    }

    fn public_inputs_delta(
        public_inputs: &[Vec<u8>],
        beta: Fr,
        gamma: Fr,
        offset: u64,
        n: u64,
    ) -> Fr {
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
        num * den.inverse()
    }
}

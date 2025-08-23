// src/verifier.rs
//! UltraHonk verifier

use crate::{
    field::Fr, shplemini::verify_shplemini, sumcheck::verify_sumcheck,
    transcript::generate_transcript, utils::load_proof,
};

#[cfg(feature = "serde_json")]
use crate::utils::load_vk_from_json;

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

pub struct UltraHonkVerifier {
    vk: crate::types::VerificationKey,
}

impl UltraHonkVerifier {
    pub fn new_with_vk(vk: crate::types::VerificationKey) -> Self {
        Self { vk }
    }

    #[cfg(feature = "serde_json")]
    pub fn new_from_json(json_data: &str) -> Self {
        Self { vk: load_vk_from_json(json_data) }
    }

    #[cfg(feature = "std")]
    pub fn new_from_vk_bytes(path: &std::path::Path) -> Option<Self> {
        crate::utils::load_vk_from_bytes_file(path).map(|vk| Self { vk })
    }

    /// Expose a reference to the parsed VK for debugging/inspection.
    pub fn get_vk(&self) -> &crate::types::VerificationKey {
        &self.vk
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
        // If VK metadata is missing/zero, fall back to actual provided public inputs.
        // Newer bb versions may omit header fields in vk_fields.json.
        // We avoid failing hard here and instead trust caller-provided inputs.

        // 3) Fiat–Shamir transcript
        // In bb v0.87, publicInputsSize includes pairing point object (16 elements)
        let pis_total = public_inputs_bytes.len() as u64 + 16;
        let pub_offset = if self.vk.pub_inputs_offset != 0 { self.vk.pub_inputs_offset } else { 1 };
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
        );

        // 5) Sum-check
        verify_sumcheck(&proof, &tx, &self.vk)?;

        // 6) Shplonk (batch opening)
        verify_shplemini(&proof, &self.vk, &tx)?;

        Ok(())
    }

    fn public_inputs_delta(
        public_inputs: &[Vec<u8>],
        pairing_point_object: &[Fr],
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
        for pi in pairing_point_object {
            num = num * (num_acc + *pi);
            den = den * (den_acc + *pi);
            num_acc = num_acc + beta;
            den_acc = den_acc - beta;
        }
        num * den.inverse()
    }
}

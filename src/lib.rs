#![no_std]
extern crate alloc;
use alloc::{boxed::Box, vec::Vec as StdVec};
use soroban_sdk::{
    contract, contracterror, contractimpl, symbol_short, Bytes, BytesN, Env, Symbol,
};
use ultrahonk_rust_verifier::{
    ec, hash, utils::load_vk_from_bytes, UltraHonkVerifier, PROOF_BYTES,
};
mod backend;
use backend::{SorobanBn254, SorobanKeccak};

/// Contract
#[contract]
pub struct UltraHonkVerifierContract;

#[contracterror]
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    VkParseError = 1,
    ProofParseError = 2,
    VerificationFailed = 3,
    VkNotSet = 4,
}

#[contractimpl]
impl UltraHonkVerifierContract {
    fn key_vk() -> Symbol {
        symbol_short!("vk")
    }

    fn key_vk_hash() -> Symbol {
        symbol_short!("vk_hash")
    }

    fn parse_public_inputs(bytes: &[u8]) -> Result<StdVec<StdVec<u8>>, Error> {
        if bytes.len() % 32 != 0 {
            return Err(Error::ProofParseError);
        }
        let mut out = StdVec::with_capacity(bytes.len() / 32);
        for chunk in bytes.chunks(32) {
            out.push(chunk.to_vec());
        }
        Ok(out)
    }

    /// Verify an UltraHonk proof.
    pub fn verify_proof(
        env: Env,
        vk_bytes: Bytes,
        public_inputs: Bytes,
        proof_bytes: Bytes,
    ) -> Result<(), Error> {
        hash::set_soroban_hash_backend(Box::new(SorobanKeccak::new(&env)));
        ec::set_soroban_bn254_backend(Box::new(SorobanBn254::new(&env)));
        let proof_vec: StdVec<u8> = proof_bytes.to_alloc_vec();
        if proof_vec.len() != PROOF_BYTES {
            return Err(Error::ProofParseError);
        }

        // Deserialize verification key bytes
        let vk_vec: StdVec<u8> = vk_bytes.to_alloc_vec();
        let vk = load_vk_from_bytes(&vk_vec);

        // Verifier (moves vk)
        let verifier = UltraHonkVerifier::new_with_vk(vk);

        // Proof & public inputs
        let pub_inputs_bytes = Self::parse_public_inputs(&public_inputs.to_alloc_vec())
            .map_err(|_| Error::ProofParseError)?;

        // Verify
        verifier
            .verify(&proof_vec, &pub_inputs_bytes)
            .map_err(|_| Error::VerificationFailed)?;
        Ok(())
    }

    /// Set verification key bytes and cache its hash. Returns vk_hash.
    /// Note: this is permissionless; integrators should add access control or immutability.
    pub fn set_vk(env: Env, vk_bytes: Bytes) -> Result<BytesN<32>, Error> {
        env.storage().instance().set(&Self::key_vk(), &vk_bytes);
        let hash_bn: BytesN<32> = env.crypto().keccak256(&vk_bytes).into();
        env.storage().instance().set(&Self::key_vk_hash(), &hash_bn);
        Ok(hash_bn)
    }

    /// Verify using the on-chain stored VK. Permissionless; relies on whoever set VK.
    pub fn verify_proof_with_stored_vk(
        env: Env,
        public_inputs: Bytes,
        proof_bytes: Bytes,
    ) -> Result<(), Error> {
        let vk_bytes: Bytes = env
            .storage()
            .instance()
            .get(&Self::key_vk())
            .ok_or(Error::VkNotSet)?;
        Self::verify_proof(env, vk_bytes, public_inputs, proof_bytes)
    }
}

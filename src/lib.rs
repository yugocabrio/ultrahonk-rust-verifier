#![no_std]
extern crate alloc;
use alloc::{boxed::Box, vec::Vec as StdVec};
use soroban_sdk::{contract, contracterror, contractimpl, symbol_short, Bytes, Env, Symbol};
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

    /// Initialize the on-chain VK once at deploy time.
    pub fn __constructor(env: Env, vk_bytes: Bytes) -> Result<(), Error> {
        env.storage().instance().set(&Self::key_vk(), &vk_bytes);
        Ok(())
    }

    /// Verify an UltraHonk proof using the stored VK.
    pub fn verify_proof(env: Env, public_inputs: Bytes, proof_bytes: Bytes) -> Result<(), Error> {
        hash::set_soroban_hash_backend(Box::new(SorobanKeccak::new(&env)));
        ec::set_soroban_bn254_backend(Box::new(SorobanBn254::new(&env)));
        let proof_vec: StdVec<u8> = proof_bytes.to_alloc_vec();
        if proof_vec.len() != PROOF_BYTES {
            return Err(Error::ProofParseError);
        }

        let vk_bytes: Bytes = env
            .storage()
            .instance()
            .get(&Self::key_vk())
            .ok_or(Error::VkNotSet)?;
        // Deserialize verification key bytes
        let vk_vec: StdVec<u8> = vk_bytes.to_alloc_vec();
        let vk = load_vk_from_bytes(&vk_vec).ok_or(Error::VkParseError)?;

        // Verifier (moves vk)
        let verifier = UltraHonkVerifier::new_with_vk(vk);

        // Proof & public inputs
        let pub_inputs_bytes = public_inputs.to_alloc_vec();

        // Verify
        verifier
            .verify(&proof_vec, &pub_inputs_bytes)
            .map_err(|_| Error::VerificationFailed)?;
        Ok(())
    }
}

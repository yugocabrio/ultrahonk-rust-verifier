use soroban_sdk::{Bytes, Env};

/// Compute Keccak-256 using the Soroban host function.
#[inline(always)]
pub fn hash32(env: &Env, data: &[u8]) -> [u8; 32] {
    let bytes = Bytes::from_slice(env, data);
    env.crypto().keccak256(&bytes).to_array()
}

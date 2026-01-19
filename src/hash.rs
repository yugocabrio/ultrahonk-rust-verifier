use soroban_sdk::Bytes;

/// Compute Keccak-256 using the Soroban host function.
#[inline(always)]
pub fn hash32(data: &Bytes) -> [u8; 32] {
    data.env().crypto().keccak256(data).to_array()
}

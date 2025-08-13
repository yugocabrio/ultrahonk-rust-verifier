use soroban_sdk::{Bytes, Env};
use ultrahonk_soroban_contract::{UltraHonkVerifierContract, UltraHonkVerifierContractClient};

// Include VK and proof artifacts produced by simple_circuit
const VK_FIELDS_JSON: &str = include_str!("../simple_circuit/target/vk_fields.json");
const PROOF_BIN: &[u8] = include_bytes!("../simple_circuit/target/proof");

#[test]
fn verify_simple_circuit_proof_succeeds() {
    let env = Env::default();
    let contract_id = env.register(UltraHonkVerifierContract, ());
    let client = UltraHonkVerifierContractClient::new(&env, &contract_id);

    // Prepare inputs
    let vk_bytes: Bytes = Bytes::from_slice(&env, VK_FIELDS_JSON.as_bytes());
    let proof_bytes: Bytes = Bytes::from_slice(&env, PROOF_BIN);

    // Verify should succeed and return a proof_id
    let proof_id = client.verify_proof(&vk_bytes, &proof_bytes);

    // Contract should record verification status under proof_id
    let verified = client.is_verified(&proof_id);
    assert!(verified, "expected proof_id to be marked verified");
}
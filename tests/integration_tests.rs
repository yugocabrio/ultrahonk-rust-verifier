use soroban_sdk::{Bytes, Env};
use ultrahonk_soroban_contract::{UltraHonkVerifierContract, UltraHonkVerifierContractClient};

#[test]
fn verify_simple_circuit_proof_succeeds() {
    let vk_fields_json: &str = include_str!("simple_circuit/target/vk_fields.json");
    let proof_bin: &[u8] = include_bytes!("simple_circuit/target/proof");

    let env = Env::default();
    let contract_id = env.register(UltraHonkVerifierContract, ());
    let client = UltraHonkVerifierContractClient::new(&env, &contract_id);

    // Prepare inputs
    let vk_bytes: Bytes = Bytes::from_slice(&env, vk_fields_json.as_bytes());
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);

    // Verify should succeed and return a proof_id
    let proof_id = client.verify_proof(&vk_bytes, &proof_bytes);

    // Contract should record verification status under proof_id
    let verified = client.is_verified(&proof_id);
    assert!(verified, "expected proof_id to be marked verified");
}

#[test]
fn verify_poseidon2_demo_proof_succeeds() {
    let vk_fields_json: &str = include_str!("poseidon2_demo/target/vk_fields.json");
    let proof_bin: &[u8] = include_bytes!("poseidon2_demo/target/proof");

    let env = Env::default();
    let contract_id = env.register(UltraHonkVerifierContract, ());
    let client = UltraHonkVerifierContractClient::new(&env, &contract_id);

    // Prepare inputs
    let vk_bytes: Bytes = Bytes::from_slice(&env, vk_fields_json.as_bytes());
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);

    // Verify should succeed and return a proof_id
    let proof_id = client.verify_proof(&vk_bytes, &proof_bytes);

    // Contract should record verification status under proof_id
    let verified = client.is_verified(&proof_id);
    assert!(verified, "expected proof_id to be marked verified");
}

#[test]
fn verify_fib_chain_proof_succeeds() {
    let vk_fields_json: &str = include_str!("fib_chain/target/vk_fields.json");
    let proof_bin: &[u8] = include_bytes!("fib_chain/target/proof");

    let env = Env::default();
    let contract_id = env.register(UltraHonkVerifierContract, ());
    let client = UltraHonkVerifierContractClient::new(&env, &contract_id);

    // Prepare inputs
    let vk_bytes: Bytes = Bytes::from_slice(&env, vk_fields_json.as_bytes());
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);

    // Verify should succeed and return a proof_id
    let proof_id = client.verify_proof(&vk_bytes, &proof_bytes);

    // Contract should record verification status under proof_id
    let verified = client.is_verified(&proof_id);
    assert!(verified, "expected proof_id to be marked verified");
}
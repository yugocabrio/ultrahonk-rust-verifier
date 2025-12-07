use soroban_sdk::{Bytes, Env};
use ultrahonk_soroban_contract::{UltraHonkVerifierContract, UltraHonkVerifierContractClient};

const CONTRACT_WASM: &[u8] = include_bytes!("../out/ultrahonk_soroban_contract.wasm");

#[test]
fn verify_simple_circuit_proof_succeeds() {
    let vk_fields_json: &str = include_str!("simple_circuit/target/vk_fields.json");
    let proof_bin: &[u8] = include_bytes!("simple_circuit/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("simple_circuit/target/public_inputs");

    let env = Env::default();

    // Prepare inputs
    let vk_bytes: Bytes = Bytes::from_slice(&env, vk_fields_json.as_bytes());
    // Pack into bytes_and_fields: [u32_be total_fields][public_inputs][proof]
    const PROOF_NUM_FIELDS: u32 = 440;
    assert!(pub_inputs_bin.len() % 32 == 0);
    let num_inputs = (pub_inputs_bin.len() / 32) as u32;
    let total_fields = PROOF_NUM_FIELDS + num_inputs;
    let mut packed: Vec<u8> = Vec::with_capacity(4 + pub_inputs_bin.len() + proof_bin.len());
    packed.extend_from_slice(&total_fields.to_be_bytes());
    packed.extend_from_slice(pub_inputs_bin);
    packed.extend_from_slice(proof_bin);
    let proof_bytes: Bytes = Bytes::from_slice(&env, &packed);

    // Register to obtain a contract ID for storage namespace
    let contract_id = env.register(UltraHonkVerifierContract, ());

    // Verify should succeed and return a proof_id (call contract impl directly under contract context)
    let proof_id = env
        .as_contract(&contract_id, || {
            UltraHonkVerifierContract::verify_proof(env.clone(), vk_bytes, proof_bytes)
        })
        .expect("verification should succeed");

    // Contract should record verification status under proof_id
    let verified = env.as_contract(&contract_id, || {
        UltraHonkVerifierContract::is_verified(env.clone(), proof_id)
    });
    assert!(verified, "expected proof_id to be marked verified");
}

#[test]
fn verify_fib_chain_proof_succeeds() {
    let vk_fields_json: &str = include_str!("fib_chain/target/vk_fields.json");
    let proof_bin: &[u8] = include_bytes!("fib_chain/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("fib_chain/target/public_inputs");

    let env = Env::default();

    // Prepare inputs
    let vk_bytes: Bytes = Bytes::from_slice(&env, vk_fields_json.as_bytes());
    const PROOF_NUM_FIELDS: u32 = 440;
    assert!(pub_inputs_bin.len() % 32 == 0);
    let num_inputs = (pub_inputs_bin.len() / 32) as u32;
    let total_fields = PROOF_NUM_FIELDS + num_inputs;
    let mut packed: Vec<u8> = Vec::with_capacity(4 + pub_inputs_bin.len() + proof_bin.len());
    packed.extend_from_slice(&total_fields.to_be_bytes());
    packed.extend_from_slice(pub_inputs_bin);
    packed.extend_from_slice(proof_bin);
    let proof_bytes: Bytes = Bytes::from_slice(&env, &packed);

    // Register to obtain a contract ID for storage namespace
    let contract_id = env.register(UltraHonkVerifierContract, ());

    // Verify should succeed and return a proof_id (call contract impl directly under contract context)
    let proof_id = env
        .as_contract(&contract_id, || {
            UltraHonkVerifierContract::verify_proof(env.clone(), vk_bytes, proof_bytes)
        })
        .expect("verification should succeed");

    // Contract should record verification status under proof_id
    let verified = env.as_contract(&contract_id, || {
        UltraHonkVerifierContract::is_verified(env.clone(), proof_id)
    });
    assert!(verified, "expected proof_id to be marked verified");
}

#[test]
fn print_budget_for_deploy_and_verify() {
    let vk_fields_json: &str = include_str!("simple_circuit/target/vk_fields.json");
    let proof_bin: &[u8] = include_bytes!("simple_circuit/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("simple_circuit/target/public_inputs");

    let env = Env::default();

    // Measure deploy (upload wasm + register) budget usage.
    env.budget().reset_unlimited();
    let wasm_bytes = Bytes::from_slice(&env, CONTRACT_WASM);
    let contract_id = env.register_contract_wasm(None, wasm_bytes);
    println!("=== Deploy budget usage ===");
    env.cost_estimate().budget().print();

    // Prepare proof inputs
    let vk_bytes: Bytes = Bytes::from_slice(&env, vk_fields_json.as_bytes());
    const PROOF_NUM_FIELDS: u32 = 440;
    assert!(pub_inputs_bin.len() % 32 == 0);
    let num_inputs = (pub_inputs_bin.len() / 32) as u32;
    let total_fields = PROOF_NUM_FIELDS + num_inputs;
    let mut packed: Vec<u8> = Vec::with_capacity(4 + pub_inputs_bin.len() + proof_bin.len());
    packed.extend_from_slice(&total_fields.to_be_bytes());
    packed.extend_from_slice(pub_inputs_bin);
    packed.extend_from_slice(proof_bin);
    let proof_bytes: Bytes = Bytes::from_slice(&env, &packed);

    // Measure verify_proof invocation budget usage in isolation.
    env.budget().reset_unlimited();
    let client = UltraHonkVerifierContractClient::new(&env, &contract_id);
    let proof_id = client.verify_proof(&vk_bytes, &proof_bytes);
    println!("=== verify_proof budget usage ===");
    env.cost_estimate().budget().print();

    let verified = client.is_verified(&proof_id);
    assert!(verified, "expected proof_id to be marked verified");
}

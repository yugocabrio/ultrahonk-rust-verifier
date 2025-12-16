use soroban_sdk::{Bytes, Env};
use ultrahonk_soroban_contract::preprocess_vk_json;

const CONTRACT_WASM: &[u8] =
    include_bytes!("../target/wasm32v1-none/release/ultrahonk_soroban_contract.wasm");

mod ultrahonk_contract {
    soroban_sdk::contractimport!(
        file = "target/wasm32v1-none/release/ultrahonk_soroban_contract.wasm"
    );
}

fn register_client<'a>(env: &'a Env) -> ultrahonk_contract::Client<'a> {
    let wasm_bytes = Bytes::from_slice(env, CONTRACT_WASM);
    let contract_id = env.register_contract_wasm(None, wasm_bytes);
    ultrahonk_contract::Client::new(env, &contract_id)
}

fn vk_bytes_from_json(env: &Env, json: &str) -> Bytes {
    let vk_blob = preprocess_vk_json(json).expect("valid vk json");
    assert_eq!(vk_blob.len(), 1824, "unexpected VK byte length");
    let bytes = Bytes::from_slice(env, &vk_blob);
    assert_eq!(bytes.len(), 1824, "unexpected Bytes len");
    bytes
}

#[test]
fn verify_simple_circuit_proof_succeeds() {
    let vk_fields_json: &str = include_str!("simple_circuit/target/vk_fields.json");
    let proof_bin: &[u8] = include_bytes!("simple_circuit/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("simple_circuit/target/public_inputs");

    let env = Env::default();
    env.budget().reset_unlimited();

    // Prepare inputs
    let vk_bytes = vk_bytes_from_json(&env, vk_fields_json);
    // Pack into bytes_and_fields: [u32_be total_fields][public_inputs][proof]
    const PROOF_NUM_FIELDS: u32 = 456;
    assert!(pub_inputs_bin.len() % 32 == 0);
    let num_inputs = (pub_inputs_bin.len() / 32) as u32;
    let total_fields = PROOF_NUM_FIELDS + num_inputs;
    let mut packed: Vec<u8> = Vec::with_capacity(4 + pub_inputs_bin.len() + proof_bin.len());
    packed.extend_from_slice(&total_fields.to_be_bytes());
    packed.extend_from_slice(pub_inputs_bin);
    packed.extend_from_slice(proof_bin);
    let proof_bytes: Bytes = Bytes::from_slice(&env, &packed);

    let client = register_client(&env);
    client.verify_proof(&vk_bytes, &proof_bytes);
}

#[test]
fn verify_fib_chain_proof_succeeds() {
    let vk_fields_json: &str = include_str!("fib_chain/target/vk_fields.json");
    let proof_bin: &[u8] = include_bytes!("fib_chain/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("fib_chain/target/public_inputs");

    let env = Env::default();
    env.budget().reset_unlimited();

    // Prepare inputs
    let vk_bytes = vk_bytes_from_json(&env, vk_fields_json);
    const PROOF_NUM_FIELDS: u32 = 456;
    assert!(pub_inputs_bin.len() % 32 == 0);
    let num_inputs = (pub_inputs_bin.len() / 32) as u32;
    let total_fields = PROOF_NUM_FIELDS + num_inputs;
    let mut packed: Vec<u8> = Vec::with_capacity(4 + pub_inputs_bin.len() + proof_bin.len());
    packed.extend_from_slice(&total_fields.to_be_bytes());
    packed.extend_from_slice(pub_inputs_bin);
    packed.extend_from_slice(proof_bin);
    let proof_bytes: Bytes = Bytes::from_slice(&env, &packed);

    let client = register_client(&env);
    client.verify_proof(&vk_bytes, &proof_bytes);
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
    let client = ultrahonk_contract::Client::new(&env, &contract_id);

    println!("=== Deploy budget usage ===");
    env.cost_estimate().budget().print();

    // Prepare proof inputs
    let vk_bytes = vk_bytes_from_json(&env, vk_fields_json);
    const PROOF_NUM_FIELDS: u32 = 456;
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
    client.verify_proof(&vk_bytes, &proof_bytes);
    println!("=== verify_proof budget usage ===");
    env.cost_estimate().budget().print();

    env.budget().reset_unlimited();
    client.set_vk(&vk_bytes);

    env.budget().reset_unlimited();
    client.verify_proof_with_stored_vk(&proof_bytes);
    println!("=== verify_proof_with_stored_vk budget usage ===");
    env.cost_estimate().budget().print();
}

#[test]
fn basic_verify_budget_test() {
    let vk_fields_json: &str = include_str!("simple_circuit/target/vk_fields.json");
    let proof_bin: &[u8] = include_bytes!("simple_circuit/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("simple_circuit/target/public_inputs");

    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();

    let contract_id = env.register(CONTRACT_WASM, ());
    let client = ultrahonk_contract::Client::new(&env, &contract_id);

    // Prepare proof inputs
    let vk_bytes = vk_bytes_from_json(&env, vk_fields_json);
    const PROOF_NUM_FIELDS: u32 = 456;
    assert!(pub_inputs_bin.len() % 32 == 0);
    let num_inputs = (pub_inputs_bin.len() / 32) as u32;
    let total_fields = PROOF_NUM_FIELDS + num_inputs;
    let mut packed: Vec<u8> = Vec::with_capacity(4 + pub_inputs_bin.len() + proof_bin.len());
    packed.extend_from_slice(&total_fields.to_be_bytes());
    packed.extend_from_slice(pub_inputs_bin);
    packed.extend_from_slice(proof_bin);
    let proof_bytes: Bytes = Bytes::from_slice(&env, &packed);
    let vk_for_direct = vk_bytes.clone();
    let proof_for_direct = proof_bytes.clone();

    client.verify_proof(&vk_for_direct, &proof_for_direct);
    env.cost_estimate().budget().print();
}

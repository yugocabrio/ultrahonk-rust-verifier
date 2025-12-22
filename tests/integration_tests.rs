use soroban_sdk::{Bytes, Env};
use ultrahonk_rust_verifier::PROOF_BYTES;

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

#[test]
fn verify_simple_circuit_proof_succeeds() {
    let vk_bytes_raw: &[u8] = include_bytes!("simple_circuit/target/vk");
    let proof_bin: &[u8] = include_bytes!("simple_circuit/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("simple_circuit/target/public_inputs");

    let env = Env::default();
    env.budget().reset_unlimited();
    assert_eq!(proof_bin.len(), PROOF_BYTES);

    // Prepare inputs
    let vk_bytes = Bytes::from_slice(&env, vk_bytes_raw);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    let client = register_client(&env);
    client.verify_proof(&vk_bytes, &public_inputs, &proof_bytes);
}

#[test]
fn verify_fib_chain_proof_succeeds() {
    let vk_bytes_raw: &[u8] = include_bytes!("fib_chain/target/vk");
    let proof_bin: &[u8] = include_bytes!("fib_chain/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("fib_chain/target/public_inputs");

    let env = Env::default();
    env.budget().reset_unlimited();
    assert_eq!(proof_bin.len(), PROOF_BYTES);

    // Prepare inputs
    let vk_bytes = Bytes::from_slice(&env, vk_bytes_raw);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    let client = register_client(&env);
    client.verify_proof(&vk_bytes, &public_inputs, &proof_bytes);
}

#[test]
fn print_budget_for_deploy_and_verify() {
    let vk_bytes_raw: &[u8] = include_bytes!("simple_circuit/target/vk");
    let proof_bin: &[u8] = include_bytes!("simple_circuit/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("simple_circuit/target/public_inputs");

    let env = Env::default();

    // Measure deploy budget usage.
    env.budget().reset_unlimited();
    let client = register_client(&env);

    println!("=== Deploy budget usage ===");
    env.cost_estimate().budget().print();

    // Prepare proof inputs
    let vk_bytes = Bytes::from_slice(&env, vk_bytes_raw);
    assert_eq!(proof_bin.len(), PROOF_BYTES);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    // Measure verify_proof invocation budget usage in isolation.
    env.budget().reset_unlimited();
    client.verify_proof(&vk_bytes, &public_inputs, &proof_bytes);
    println!("=== verify_proof budget usage ===");
    env.cost_estimate().budget().print();

    env.budget().reset_unlimited();
    client.set_vk(&vk_bytes);

    env.budget().reset_unlimited();
    client.verify_proof_with_stored_vk(&public_inputs, &proof_bytes);
    println!("=== verify_proof_with_stored_vk budget usage ===");
    env.cost_estimate().budget().print();
}

#[test]
fn basic_verify_budget_test() {
    let vk_bytes_raw: &[u8] = include_bytes!("simple_circuit/target/vk");
    let proof_bin: &[u8] = include_bytes!("simple_circuit/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("simple_circuit/target/public_inputs");

    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();

    let client = register_client(&env);

    // Prepare proof inputs
    let vk_bytes = Bytes::from_slice(&env, vk_bytes_raw);
    assert_eq!(proof_bin.len(), PROOF_BYTES);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);
    let vk_for_direct = vk_bytes.clone();
    let proof_for_direct = proof_bytes.clone();
    let public_inputs_for_direct = public_inputs.clone();

    client.verify_proof(&vk_for_direct, &public_inputs_for_direct, &proof_for_direct);
    env.cost_estimate().budget().print();
}

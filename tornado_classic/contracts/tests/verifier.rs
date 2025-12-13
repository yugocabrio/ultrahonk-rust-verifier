use soroban_env_host::DiagnosticLevel;
use soroban_sdk::{Address, Bytes, Env};

use std::sync::{Mutex, OnceLock};

use ultrahonk_soroban_contract::{preprocess_vk_json, UltraHonkVerifierContract};

fn verify_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn vk_bytes_from_json(env: &Env, json: &str) -> Bytes {
    let blob = preprocess_vk_json(json).expect("valid vk json");
    Bytes::from_slice(env, &blob)
}

// Verifier: direct call with vk_json + packed bytes
#[test]
fn verify_proof_direct_with_vk_json() {
    let _guard = verify_lock().lock().unwrap();
    let env = Env::default();
    env.budget().reset_unlimited();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);

    let vk_fields_json: &str = include_str!("../../circuit/target/vk_fields.json");
    let proof_bin: &[u8] = include_bytes!("../../circuit/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("../../circuit/target/public_inputs");

    // Pack inputs: [u32_be total_fields][public_inputs][proof]
    const PROOF_NUM_FIELDS: u32 = 456;
    assert!(pub_inputs_bin.len() % 32 == 0);
    let num_inputs = (pub_inputs_bin.len() / 32) as u32;
    let total_fields = PROOF_NUM_FIELDS + num_inputs;
    let mut packed: Vec<u8> = Vec::with_capacity(4 + pub_inputs_bin.len() + proof_bin.len());
    packed.extend_from_slice(&total_fields.to_be_bytes());
    packed.extend_from_slice(pub_inputs_bin);
    packed.extend_from_slice(proof_bin);

    let verifier_id: Address = env.register(UltraHonkVerifierContract, ());
    let vk_bytes: Bytes = vk_bytes_from_json(&env, vk_fields_json);
    let proof_bytes: Bytes = Bytes::from_slice(&env, &packed);

    env
        .as_contract(&verifier_id, || {
            UltraHonkVerifierContract::verify_proof(env.clone(), vk_bytes.clone(), proof_bytes.clone())
        })
        .expect("verification should succeed");
}

// Verifier: store VK on-chain and use stored VK path
#[test]
fn verify_proof_with_stored_vk_path() {
    let _guard = verify_lock().lock().unwrap();
    let env = Env::default();
    env.budget().reset_unlimited();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);

    let vk_fields_json: &str = include_str!("../../circuit/target/vk_fields.json");
    let proof_bin: &[u8] = include_bytes!("../../circuit/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("../../circuit/target/public_inputs");

    const PROOF_NUM_FIELDS: u32 = 456;
    assert!(pub_inputs_bin.len() % 32 == 0);
    let num_inputs = (pub_inputs_bin.len() / 32) as u32;
    let total_fields = PROOF_NUM_FIELDS + num_inputs;
    let mut packed: Vec<u8> = Vec::with_capacity(4 + pub_inputs_bin.len() + proof_bin.len());
    packed.extend_from_slice(&total_fields.to_be_bytes());
    packed.extend_from_slice(pub_inputs_bin);
    packed.extend_from_slice(proof_bin);

    let verifier_id: Address = env.register(UltraHonkVerifierContract, ());

    // set_vk then call with stored VK
    let vk_bytes: Bytes = vk_bytes_from_json(&env, vk_fields_json);
    env.as_contract(&verifier_id, || UltraHonkVerifierContract::set_vk(env.clone(), vk_bytes.clone()))
        .expect("set_vk ok");

    let proof_bytes: Bytes = Bytes::from_slice(&env, &packed);
    env
        .as_contract(&verifier_id, || UltraHonkVerifierContract::verify_proof_with_stored_vk(env.clone(), proof_bytes.clone()))
        .expect("verification ok");
}

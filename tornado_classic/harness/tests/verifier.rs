use soroban_env_host::DiagnosticLevel;
use soroban_sdk::{Address, Bytes, BytesN, Env};

use ultrahonk_soroban_contract::UltraHonkVerifierContract;

// Verifier: direct call with vk_json + packed bytes
#[test]
fn verify_proof_direct_with_vk_json() {
    let env = Env::default();
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
    let vk_bytes: Bytes = Bytes::from_slice(&env, vk_fields_json.as_bytes());
    let proof_bytes: Bytes = Bytes::from_slice(&env, &packed);

    let proof_id: BytesN<32> = env
        .as_contract(&verifier_id, || {
            UltraHonkVerifierContract::verify_proof(env.clone(), vk_bytes.clone(), proof_bytes.clone())
        })
        .expect("verification should succeed");

    let verified = env.as_contract(&verifier_id, || {
        UltraHonkVerifierContract::is_verified(env.clone(), proof_id.clone())
    });
    assert!(verified);
}

// Verifier: store VK on-chain and use stored VK path
#[test]
fn verify_proof_with_stored_vk_path() {
    let env = Env::default();
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
    let vk_bytes: Bytes = Bytes::from_slice(&env, vk_fields_json.as_bytes());
    env.as_contract(&verifier_id, || UltraHonkVerifierContract::set_vk(env.clone(), vk_bytes.clone()))
        .expect("set_vk ok");

    let proof_bytes: Bytes = Bytes::from_slice(&env, &packed);
    let proof_id: BytesN<32> = env
        .as_contract(&verifier_id, || UltraHonkVerifierContract::verify_proof_with_stored_vk(env.clone(), proof_bytes.clone()))
        .expect("verification ok");

    let verified = env.as_contract(&verifier_id, || {
        UltraHonkVerifierContract::is_verified(env.clone(), proof_id.clone())
    });
    assert!(verified);
}

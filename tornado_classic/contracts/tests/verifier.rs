use soroban_env_host::DiagnosticLevel;
use soroban_sdk::{Address, Bytes, Env};

use std::sync::{Mutex, OnceLock};

use rs_soroban_ultrahonk::UltraHonkVerifierContract;
use ultrahonk_soroban_verifier::PROOF_BYTES;

fn verify_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
fn verify_proof_with_constructor_vk() {
    let _guard = verify_lock().lock().unwrap();
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);

    let vk_bin: &[u8] = include_bytes!("../../circuit/target/vk");
    let proof_bin: &[u8] = include_bytes!("../../circuit/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("../../circuit/target/public_inputs");

    assert_eq!(proof_bin.len(), PROOF_BYTES);

    let vk_bytes: Bytes = Bytes::from_slice(&env, vk_bin);
    let verifier_id: Address = env.register(UltraHonkVerifierContract, (vk_bytes.clone(),));
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    env.as_contract(&verifier_id, || {
        UltraHonkVerifierContract::verify_proof(
            env.clone(),
            public_inputs.clone(),
            proof_bytes.clone(),
        )
    })
    .expect("verification should succeed");

}

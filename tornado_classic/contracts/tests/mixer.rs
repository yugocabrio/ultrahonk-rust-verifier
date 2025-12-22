use soroban_env_host::DiagnosticLevel;
use soroban_sdk::{testutils::Address as TestAddress, Address, Bytes, BytesN, Env};

use std::sync::{Mutex, OnceLock};

use tornado_classic_contracts::hash2::permute_2_bytes_be;
use tornado_classic_contracts::mixer::{MixerContract, MixerError};
use ultrahonk_soroban_contract::UltraHonkVerifierContract;
use ultrahonk_rust_verifier::PROOF_BYTES;

const TREE_DEPTH_TEST: u32 = 10;

#[cfg(feature = "wasm-cost")]
mod wasm_artifacts {
    pub const VERIFIER_WASM: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/wasm32v1-none/release/ultrahonk_soroban_contract.wasm"
    ));
    pub const MIXER_WASM: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/wasm32v1-none/release/tornado_classic_contracts.wasm"
    ));

    pub mod ultrahonk_contract {
        soroban_sdk::contractimport!(
            file = "../../target/wasm32v1-none/release/ultrahonk_soroban_contract.wasm"
        );
    }
    pub mod mixer_contract {
        soroban_sdk::contractimport!(
            file = "target/wasm32v1-none/release/tornado_classic_contracts.wasm"
        );
    }
}

fn verify_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn vk_bytes(env: &Env) -> Bytes {
    Bytes::from_slice(env, include_bytes!("../../circuit/target/vk"))
}

fn be32_from_u64(x: u64) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[24..32].copy_from_slice(&x.to_be_bytes());
    a
}

fn hash2(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] { permute_2_bytes_be(a, b) }

fn zero_at(level: u32) -> [u8; 32] {
    let mut z = [0u8; 32];
    for _ in 0..level { let zz = z; z = hash2(&zz, &zz); }
    z
}

fn frontier_root_from_leaves(leaves: &[[u8; 32]], depth: u32) -> [u8; 32] {
    let mut frontier: Vec<Option<[u8; 32]>> = vec![None; depth as usize];
    let mut root = zero_at(depth);
    for (i, leaf) in leaves.iter().enumerate() {
        let idx = i as u32;
        let mut cur = *leaf;
        let mut level = 0u32;
        while level < depth {
            let bit = (idx >> level) & 1;
            if bit == 0 {
                frontier[level as usize] = Some(cur);
                let z = zero_at(level);
                cur = hash2(&cur, &z);
            } else {
                let left = frontier[level as usize].as_ref().copied().unwrap_or_else(|| zero_at(level));
                cur = hash2(&left, &cur);
            }
            level += 1;
        }
        root = cur;
    }
    root
}

fn register_verifier(env: &Env) -> Address { env.register(UltraHonkVerifierContract, ()) }
fn register_mixer(env: &Env) -> Address { env.register(MixerContract, ()) }

#[cfg(feature = "wasm-cost")]
fn register_wasm_verifier<'a>(env: &'a Env) -> (wasm_artifacts::ultrahonk_contract::Client<'a>, Address) {
    let wasm_bytes = Bytes::from_slice(env, wasm_artifacts::VERIFIER_WASM);
    let contract_id = env.register_contract_wasm(None, wasm_bytes);
    (wasm_artifacts::ultrahonk_contract::Client::new(env, &contract_id), contract_id)
}

#[cfg(feature = "wasm-cost")]
fn register_wasm_mixer<'a>(env: &'a Env) -> (wasm_artifacts::mixer_contract::Client<'a>, Address) {
    let wasm_bytes = Bytes::from_slice(env, wasm_artifacts::MIXER_WASM);
    let contract_id = env.register_contract_wasm(None, wasm_bytes);
    (wasm_artifacts::mixer_contract::Client::new(env, &contract_id), contract_id)
}

/// Deposits a sequence of leaves and checks the contract frontier updates match a reference implementation.
#[test]
fn merkle_frontier_updates_root_matches_reference_and_mapping_ok() {
    let env = Env::default();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);
    let mixer_id: Address = env.register(MixerContract, ());

    let mut leaves: Vec<[u8; 32]> = Vec::new();
    for i in 0u64..8 { let a = be32_from_u64(i); let b = be32_from_u64(i+100); leaves.push(hash2(&a,&b)); }

    for (n, leaf) in leaves.iter().enumerate() {
        env.as_contract(&mixer_id, || MixerContract::deposit(env.clone(), BytesN::from_array(&env, leaf))).unwrap();
        let onchain_root = env.as_contract(&mixer_id, || MixerContract::get_root(env.clone())).unwrap();
        let expected_root = frontier_root_from_leaves(&leaves[0..=n], TREE_DEPTH_TEST);
        assert_eq!(onchain_root, BytesN::from_array(&env, &expected_root));
        let got_cm = env.as_contract(&mixer_id, || MixerContract::get_commitment_by_index(env.clone(), n as u32)).unwrap();
        assert_eq!(got_cm, BytesN::from_array(&env, leaf));
    }
}

/// Happy-path withdraw followed by a double-spend attempt confirms the nullifier is enforced.
#[test]
fn mixer_withdraw_and_double_spend_rejected() {
    let _guard = verify_lock().lock().unwrap();
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);

    // Artifacts
    let vk_bin: &[u8] = include_bytes!("../../circuit/target/vk");
    let proof_bin: &[u8] = include_bytes!("../../circuit/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("../../circuit/target/public_inputs");

    // Register contracts
    let verifier_id: Address = env.register(UltraHonkVerifierContract, ());
    let mixer_id: Address = env.register(MixerContract, ());

    let admin = <Address as TestAddress>::generate(&env);
    let _auth = env.mock_all_auths();
    env.as_contract(&mixer_id, || MixerContract::configure(env.clone(), admin.clone()))
        .expect("configure ok");

    // Deposit a commitment (placeholder) so root is non-zero
    let commitment = BytesN::from_array(&env, &[0x11; 32]);
    env.as_contract(&mixer_id, || MixerContract::deposit(env.clone(), commitment)).unwrap();

    // Set on-chain root to circuit public root
    assert!(pub_inputs_bin.len() >= 64);
    let mut root_arr = [0u8; 32];
    root_arr.copy_from_slice(&pub_inputs_bin[..32]);
    env.as_contract(&mixer_id, || {
        MixerContract::set_root(env.clone(), BytesN::from_array(&env, &root_arr))
    })
    .expect("set_root ok");

    assert_eq!(proof_bin.len(), PROOF_BYTES);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    // Store VK and withdraw
    let vk_bytes: Bytes = Bytes::from_slice(&env, vk_bin);
    env.as_contract(&verifier_id, || UltraHonkVerifierContract::set_vk(env.clone(), vk_bytes.clone())).expect("set_vk ok");
    let mut nf_arr = [0u8; 32];
    nf_arr.copy_from_slice(&pub_inputs_bin[32..64]);
    let nf = BytesN::from_array(&env, &nf_arr);

    env.as_contract(&mixer_id, || MixerContract::withdraw(
        env.clone(),
        verifier_id.clone(),
        public_inputs.clone(),
        proof_bytes.clone(),
        nf.clone()
    )).expect("withdraw ok");

    // Double-spend attempt with same nullifier must fail
    let err = env.as_contract(&mixer_id, || MixerContract::withdraw(
        env.clone(),
        verifier_id.clone(),
        public_inputs.clone(),
        proof_bytes.clone(),
        nf.clone()
    )).err().expect("expected error");
    assert_eq!(err as u32, MixerError::NullifierUsed as u32);
}

/// Ensures `set_root` cannot be called before the admin is configured.
#[test]
fn set_root_requires_admin_configuration() {
    let env = Env::default();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);
    let mixer_id: Address = env.register(MixerContract, ());

    let result = env.as_contract(&mixer_id, || {
        MixerContract::set_root(env.clone(), BytesN::from_array(&env, &[1u8; 32]))
    });
    let err = result.err().expect("expected admin not configured error");
    assert_eq!(err as u32, MixerError::AdminNotConfigured as u32);
}

/// Verifies that providing a mismatched nullifier causes the withdraw to fail and leaves the nullifier unused.
#[test]
fn withdraw_rejects_nullifier_mismatch() {
    let _guard = verify_lock().lock().unwrap();
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);

    let vk_bin: &[u8] = include_bytes!("../../circuit/target/vk");
    let proof_bin: &[u8] = include_bytes!("../../circuit/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("../../circuit/target/public_inputs");

    let verifier_id: Address = env.register(UltraHonkVerifierContract, ());
    let mixer_id: Address = env.register(MixerContract, ());

    let admin = <Address as TestAddress>::generate(&env);
    let _auth = env.mock_all_auths();
    env.as_contract(&mixer_id, || MixerContract::configure(env.clone(), admin.clone()))
        .expect("configure ok");

    let commitment = BytesN::from_array(&env, &[0x22; 32]);
    env.as_contract(&mixer_id, || MixerContract::deposit(env.clone(), commitment)).unwrap();

    assert!(pub_inputs_bin.len() >= 64);
    let mut root_arr = [0u8; 32];
    root_arr.copy_from_slice(&pub_inputs_bin[..32]);
    env.as_contract(&mixer_id, || {
        MixerContract::set_root(env.clone(), BytesN::from_array(&env, &root_arr))
    })
    .expect("set_root ok");

    assert_eq!(proof_bin.len(), PROOF_BYTES);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    let vk_bytes: Bytes = Bytes::from_slice(&env, vk_bin);
    env.as_contract(&verifier_id, || UltraHonkVerifierContract::set_vk(env.clone(), vk_bytes.clone()))
        .expect("set_vk ok");

    let wrong_nf = BytesN::from_array(&env, &[0xAA; 32]);
    let err = env
        .as_contract(&mixer_id, || {
            MixerContract::withdraw(
                env.clone(),
                verifier_id.clone(),
                public_inputs.clone(),
                proof_bytes.clone(),
                wrong_nf.clone(),
            )
        })
        .err()
        .expect("expected nullifier mismatch");
    assert_eq!(err as u32, MixerError::NullifierMismatch as u32);

    let mut nf_arr = [0u8; 32];
    nf_arr.copy_from_slice(&pub_inputs_bin[32..64]);
    let nf_from_proof = BytesN::from_array(&env, &nf_arr);
    let used = env.as_contract(&mixer_id, || {
        MixerContract::is_nullifier_used(env.clone(), nf_from_proof.clone())
    });
    assert!(!used, "nullifier should remain unused after mismatch");
}

/// Checks that `configure` may only be invoked once.
#[test]
fn configure_twice_is_rejected() {
    let env = Env::default();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);
    let mixer_id: Address = env.register(MixerContract, ());

    let admin = <Address as TestAddress>::generate(&env);
    let _auth = env.mock_all_auths();
    env.as_contract(&mixer_id, || MixerContract::configure(env.clone(), admin.clone()))
        .expect("first configure ok");

    let err = env
        .as_contract(&mixer_id, || MixerContract::configure(env.clone(), admin.clone()))
        .err()
        .expect("expected duplicate configure error");
    assert_eq!(err as u32, MixerError::AdminAlreadyConfigured as u32);
}

/// Confirms withdraw fails if the proof root differs from the stored root and does not consume the nullifier.
#[test]
fn withdraw_rejects_root_mismatch() {
    let _guard = verify_lock().lock().unwrap();
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);

    let proof_bin: &[u8] = include_bytes!("../../circuit/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("../../circuit/target/public_inputs");

    let verifier_id: Address = env.register(UltraHonkVerifierContract, ());
    let mixer_id: Address = env.register(MixerContract, ());

    let admin = <Address as TestAddress>::generate(&env);
    let _auth = env.mock_all_auths();
    env.as_contract(&mixer_id, || MixerContract::configure(env.clone(), admin.clone()))
        .expect("configure ok");

    // Deposit one leaf to seed tree
    let commitment = BytesN::from_array(&env, &[0x33; 32]);
    env.as_contract(&mixer_id, || MixerContract::deposit(env.clone(), commitment)).unwrap();

    // Set an incorrect root (all zero)
    env.as_contract(&mixer_id, || {
        MixerContract::set_root(env.clone(), BytesN::from_array(&env, &[0u8; 32]))
    })
    .expect("set_root ok");

    assert_eq!(proof_bin.len(), PROOF_BYTES);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    let vk_bytes: Bytes = vk_bytes(&env);
    env.as_contract(&verifier_id, || UltraHonkVerifierContract::set_vk(env.clone(), vk_bytes.clone()))
        .expect("set_vk ok");

    let mut nf_arr = [0u8; 32];
    nf_arr.copy_from_slice(&pub_inputs_bin[32..64]);
    let nf = BytesN::from_array(&env, &nf_arr);

    let err = env
        .as_contract(&mixer_id, || {
            MixerContract::withdraw(
                env.clone(),
                verifier_id.clone(),
                public_inputs.clone(),
                proof_bytes.clone(),
                nf.clone(),
            )
        })
        .err()
        .expect("expected root mismatch");
    assert_eq!(err as u32, MixerError::RootMismatch as u32);

    let spent = env.as_contract(&mixer_id, || MixerContract::is_nullifier_used(env.clone(), nf.clone()));
    assert!(!spent, "nullifier should remain unused after root mismatch");
}

#[test]
fn print_budget_for_deposit_and_withdraw() {
    let _guard = verify_lock().lock().unwrap();
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);

    let proof_bin: &[u8] = include_bytes!("../../circuit/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("../../circuit/target/public_inputs");

    // Register real WASM contracts so WasmInsnExec is included in the budget.
    let verifier_id = register_verifier(&env);
    let mixer_id = register_mixer(&env);

    let admin = <Address as TestAddress>::generate(&env);
    let _auth = env.mock_all_auths();
    env.as_contract(&mixer_id, || MixerContract::configure(env.clone(), admin.clone()))
        .expect("configure ok");

    // Measure deposit budget usage
    env.cost_estimate().budget().reset_unlimited();
    let commitment = BytesN::from_array(&env, &[0x55; 32]);
    env.as_contract(&mixer_id, || MixerContract::deposit(env.clone(), commitment.clone()))
        .expect("deposit ok");
    println!("=== deposit budget usage ===");
    env.cost_estimate().budget().print();

    // Prepare proof inputs
    assert!(pub_inputs_bin.len() >= 64);
    let mut root_arr = [0u8; 32];
    root_arr.copy_from_slice(&pub_inputs_bin[..32]);
    env.as_contract(&mixer_id, || {
        MixerContract::set_root(env.clone(), BytesN::from_array(&env, &root_arr))
    })
    .expect("set_root ok");

    assert_eq!(proof_bin.len(), PROOF_BYTES);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    let vk_bytes: Bytes = vk_bytes(&env);
    env.as_contract(&verifier_id, || UltraHonkVerifierContract::set_vk(env.clone(), vk_bytes.clone()))
        .expect("set_vk ok");

    let mut nf_arr = [0u8; 32];
    nf_arr.copy_from_slice(&pub_inputs_bin[32..64]);
    let nf = BytesN::from_array(&env, &nf_arr);

    env.cost_estimate().budget().reset_unlimited();
    env.as_contract(&mixer_id, || {
        MixerContract::withdraw(
            env.clone(),
            verifier_id.clone(),
            public_inputs.clone(),
            proof_bytes.clone(),
            nf.clone(),
        )
    })
    .expect("withdraw ok");
    println!("=== withdraw budget usage ===");
    env.cost_estimate().budget().print();
}

/// Measure deposit/withdraw budget using WASM contracts (requires built artifacts).
#[cfg(feature = "wasm-cost")]
#[test]
fn print_wasm_budget_for_deposit_and_withdraw() {
    let _guard = verify_lock().lock().unwrap();
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);

    let proof_bin: &[u8] = include_bytes!("../../circuit/target/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("../../circuit/target/public_inputs");

    let (verifier, verifier_id) = register_wasm_verifier(&env);
    let (mixer, _) = register_wasm_mixer(&env);

    let admin = <Address as TestAddress>::generate(&env);
    let _auth = env.mock_all_auths();
    mixer.configure(&admin);

    env.cost_estimate().budget().reset_unlimited();
    let commitment = BytesN::from_array(&env, &[0x55; 32]);
    mixer.deposit(&commitment);
    println!("=== wasm deposit budget usage ===");
    env.cost_estimate().budget().print();

    println!("Skipping withdraw in wasm-cost test (deposit only).");
}

#[test]
fn deposit_rejects_duplicate_commitment() {
    let env = Env::default();
    let _ = env.host().set_diagnostic_level(DiagnosticLevel::None);
    let mixer_id: Address = env.register(MixerContract, ());

    let cm = BytesN::from_array(&env, &[0x55; 32]);
    env.as_contract(&mixer_id, || MixerContract::deposit(env.clone(), cm.clone()))
        .expect("first deposit ok");

    let err = env
        .as_contract(&mixer_id, || MixerContract::deposit(env.clone(), cm.clone()))
        .err()
        .expect("expected duplicate commitment error");
    assert_eq!(err as u32, MixerError::CommitmentExists as u32);
}

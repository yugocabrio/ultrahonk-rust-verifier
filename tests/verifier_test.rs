use std::{fs, path::Path};
use ultrahonk_rust_verifier::{load_proof_and_public_inputs, UltraHonkVerifier};

fn run(dir: &str) -> Result<(), String> {
    let path = Path::new(dir);

    let proof_buf = fs::read(path.join("proof")).map_err(|e| e.to_string())?;
    let (pub_inputs, proof_bytes) = load_proof_and_public_inputs(&proof_buf);

    let vk_path = path.join("vk_fields.json");
    let verifier = UltraHonkVerifier::new(vk_path.to_str().unwrap());

    let pub_inputs_bytes: Vec<Vec<u8>> =
        pub_inputs.iter().map(|fr| fr.to_bytes().to_vec()).collect();

    verifier.verify(&proof_bytes, &pub_inputs_bytes)?;
    Ok(())
}

#[test]
fn simple_circuit_proof_verifies() -> Result<(), String> {
    run("circuits/simple_circuit/target")
}

#[test]
fn fib_chain_proof_verifies() -> Result<(), String> {
    run("circuits/fib_chain/target")
}

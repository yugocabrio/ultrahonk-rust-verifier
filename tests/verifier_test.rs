use std::{fs, path::Path};
use ultrahonk_rust_verifier::UltraHonkVerifier;

fn run(dir: &str) -> Result<(), String> {
    let path = Path::new(dir);

    // Proof bytes
    let proof_bytes: Vec<u8> = fs::read(path.join("proof")).map_err(|e| e.to_string())?;

    // Use binary VK
    let vk_bytes = fs::read(path.join("vk")).map_err(|e| e.to_string())?;
    let verifier = UltraHonkVerifier::new_from_bytes(&vk_bytes).map_err(String::from)?;

    // Public inputs bytes
    let public_inputs = fs::read(path.join("public_inputs")).map_err(|e| e.to_string())?;
    verifier.verify(&proof_bytes, &public_inputs)?;
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

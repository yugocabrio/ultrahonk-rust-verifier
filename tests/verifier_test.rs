use std::{fs, path::Path};
use ultrahonk_rust_verifier::UltraHonkVerifier;

fn run(dir: &str) -> Result<(), String> {
    let path = Path::new(dir);

    // Proof bytes
    let proof_bytes: Vec<u8> = fs::read(path.join("proof")).map_err(|e| e.to_string())?;

    // Use JSON VK
    let vk_json = fs::read_to_string(path.join("vk_fields.json")).map_err(|e| e.to_string())?;
    let verifier = UltraHonkVerifier::new_from_json(&vk_json);

    // Public inputs bytes
    let buf = fs::read(path.join("public_inputs")).map_err(|e| e.to_string())?;
    assert!(
        buf.len() % 32 == 0,
        "public_inputs must be multiple of 32 bytes"
    );
    let mut pub_inputs_bytes: Vec<Vec<u8>> = Vec::with_capacity(buf.len() / 32);
    for chunk in buf.chunks(32) {
        pub_inputs_bytes.push(chunk.to_vec());
    }

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

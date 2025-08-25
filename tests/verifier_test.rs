use std::{fs, path::Path};
use ultrahonk_rust_verifier::UltraHonkVerifier;
 

fn run(dir: &str) -> Result<(), String> {
    let path = Path::new(dir);

    // Prefer raw proof bytes; fallback to JSON fields if missing
    let proof_path = path.join("proof");
    let proof_bytes: Vec<u8> = if proof_path.exists() {
        fs::read(&proof_path).map_err(|e| e.to_string())?
    } else {
        let proof_fields_json = fs::read_to_string(path.join("proof_fields.json")).map_err(|e| e.to_string())?;
        let proof_fields: Vec<String> = serde_json::from_str(&proof_fields_json).map_err(|e| e.to_string())?;
        let mut out: Vec<u8> = Vec::with_capacity(proof_fields.len() * 32);
        for h in proof_fields {
            let raw = h.trim_start_matches("0x");
            let bytes = hex::decode(raw).map_err(|e| e.to_string())?;
            let mut padded = vec![0u8; 32 - bytes.len()];
            padded.extend_from_slice(&bytes);
            out.extend_from_slice(&padded);
        }
        out
    };

    // Use JSON VK for deterministic ordering (bb v0.87)
    let vk_json = fs::read_to_string(path.join("vk_fields.json")).map_err(|e| e.to_string())?;
    let verifier = UltraHonkVerifier::new_from_json(&vk_json);

    // Public inputs: prefer raw bytes; fallback to JSON fields
    let mut pub_inputs_bytes: Vec<Vec<u8>> = Vec::new();
    let pub_inputs_path = path.join("public_inputs");
    if pub_inputs_path.exists() {
        let buf = fs::read(&pub_inputs_path).map_err(|e| e.to_string())?;
        assert!(buf.len() % 32 == 0, "public_inputs must be multiple of 32 bytes");
        for chunk in buf.chunks(32) { pub_inputs_bytes.push(chunk.to_vec()); }
    } else {
        let pub_inputs_fields_json =
            fs::read_to_string(path.join("public_inputs_fields.json")).map_err(|e| e.to_string())?;
        let pub_inputs_fields: Vec<String> = serde_json::from_str(&pub_inputs_fields_json).map_err(|e| e.to_string())?;
        pub_inputs_bytes.reserve(pub_inputs_fields.len());
        for h in pub_inputs_fields {
            let raw = h.trim_start_matches("0x");
            let bytes = hex::decode(raw).map_err(|e| e.to_string())?;
            let mut padded = vec![0u8; 32 - bytes.len()];
            padded.extend_from_slice(&bytes);
            pub_inputs_bytes.push(padded);
        }
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

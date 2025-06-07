// src/lib.rs

pub mod crypto;
pub mod field;
pub mod relations;
pub mod transcript;
pub mod types;
pub mod utils;
pub mod verifier;
pub mod sumcheck;
pub mod shplonk;

pub use utils::load_proof_and_public_inputs;
pub use verifier::HonkVerifier;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    #[test]
    fn test_simple_proof() -> Result<(), String> {
        // 1) Load proof+inputs
        let fixtures = Path::new("tests/fixtures");
        let mut buf = Vec::new();
        File::open(fixtures.join("simple_proof.bin"))
            .map_err(|e| e.to_string())?
            .read_to_end(&mut buf)
            .map_err(|e| e.to_string())?;
        let (pub_inputs, proof_bytes) = load_proof_and_public_inputs(&buf);

        // 2) Load VK JSON (hex strings)
        let vk_path = fixtures.join("simple_vk.json");
        // 3) Verify
        let verifier = HonkVerifier::new(vk_path.to_str().unwrap());
        // serialize pub inputs
        let mut inp_bytes = Vec::new();
        for fr in pub_inputs {
            let mut b = [0u8; 32];
            b.copy_from_slice(&fr.to_bytes());
            inp_bytes.push(b.to_vec());
        }
        verifier.verify(&proof_bytes, &inp_bytes)?;
        println!("✅ Verification succeeded");
        Ok(())
    }
}

# UltraHonk Rust Verifier 🦀
Rust verifier library for proofs generated from Noir (UltraHonk) on BN254, with minimal dependencies. Its purpose is to verify Noir/UltraHonk proofs produced by Nargo 1.0.0-beta.9 + barretenberg (bb v0.87.0). A small Noir asset is included only for testing the verifier.

---

## Features
- Verifies proofs generated from Noir (UltraHonk) using Nargo 1.0.0-beta.9 / barretenberg v0.87.0  
- Pure Rust core; `no_std` + `alloc` friendly  
- Supports bb `write_vk --output_format bytes_and_fields` (`vk_fields.json`)  
- Example verification inputs under `circuits/simple_circuit/target` (for tests)

---

## Quick Start
```bash
cargo test --features "std"

cargo test
```

## How It Works
- Typical pipeline: Noir circuit → Nargo prove → bb emits `proof`, `public_inputs`, `vk_fields.json` → this library verifies the proof.
- Test data (already checked in) lives at `circuits/simple_circuit/target` and includes:
  - `proof` (raw bytes)
  - `public_inputs` (raw bytes) or `public_inputs_fields.json`
- `vk_fields.json` (array of hex field elements; Noir/Nargo 1.0.0-beta.9 + bb v0.87.0 layout)
- The test at `tests/verifier_test.rs` loads these files and calls the Rust verifier.

---

## Crate Usage

Add the dependency from a git path or local path. The crate exposes a small API:

```rust
use ultrahonk_rust_verifier::UltraHonkVerifier;

// If you have a vk_fields.json string (Noir/Nargo 1.0.0-beta.9, bb v0.87.0)
let vk_json = std::fs::read_to_string("vk_fields.json").unwrap();
let verifier = UltraHonkVerifier::new_from_json(&vk_json);

// Load proof bytes and public inputs as 32‑byte big‑endian chunks
let proof_bytes = std::fs::read("proof").unwrap();
let public_inputs_bytes: Vec<Vec<u8>> = {
    let buf = std::fs::read("public_inputs").unwrap();
    assert!(buf.len() % 32 == 0);
    buf.chunks(32).map(|c| c.to_vec()).collect()
};

verifier.verify(&proof_bytes, &public_inputs_bytes).unwrap();
```

Notes:
- Library scope: verification only (not a prover or circuit compiler). Input files must be produced by Noir/Nargo 1.0.0-beta.9 + bb v0.87.0.
- The verifier internally re-derives the Fiat–Shamir transcript and checks both Sum‑check and Shplonk batch openings over BN254.
- `std` feature enables file I/O and serde JSON; the core logic is `no_std` + `alloc` friendly.
- Enable the `trace` feature to print step-by-step internals for cross‑checking with Solidity outputs.

## Cargo Features
- `std`: enables I/O and serde for convenient loading.
- `trace`: prints detailed verifier internals (for debugging); off by default.
- `alloc` (default): required for `no_std` collections.
- `soroban-bn254-precompile`: routes MSM + pairing calls through a backend facade intended for a Soroban BN254 precompile.
  For now, it falls back to Arkworks so behavior is unchanged, but gives a stable call site to switch to host calls later.

### Soroban BN254 precompile
- Purpose: Provide a seam to swap the EC hot paths (G1 MSM and pairing) to a Soroban BN254 precompile.
- Enable: `--features soroban-bn254-precompile`. If no backend is registered, it transparently falls back to the Arkworks implementation.
- Scope: Public API remains unchanged (`ec::g1_msm`, `ec::pairing_check`). Register a backend once at startup.

Backend contract
- Trait: `ec::Bn254Ops` (intended to be `Send + Sync`)
  - `fn g1_msm(&self, coms: &[G1Point], scalars: &[Fr]) -> Result<G1Affine, String>`
    - Requirements: `coms.len() == scalars.len()`. G1 inputs are affine. Reject off-curve or wrong-subgroup points.
  - `fn pairing_check(&self, p0: &G1Affine, p1: &G1Affine) -> bool`
    - Must verify `e(p0, rhs_g2) * e(p1, lhs_g2) == 1` using the fixed G2 constants defined in `ec.rs`.

```
#[cfg(feature = "soroban-bn254-precompile")]
{
    use ultrahonk_rust_verifier::{ec::{self, Bn254Ops}, types::G1Point, field::Fr};
    use ark_bn254::G1Affine;

    // Example backend that calls the Soroban host precompile (pseudo-code)
    struct SorobanOps { /* env: soroban_sdk::Env, ... */ }
    impl Bn254Ops for SorobanOps {
        fn g1_msm(&self, coms: &[G1Point], scalars: &[Fr]) -> Result<G1Affine, String> {
            // host_msm(env, coms, scalars).map_err(|e| e.to_string())
            unimplemented!("call Soroban MSM precompile")
        }
        fn pairing_check(&self, p0: &G1Affine, p1: &G1Affine) -> bool {
            // host_pairing_check(env, p0, p1)
            unimplemented!("call Soroban pairing precompile")
        }
    }

    ec::set_soroban_bn254_backend(Box::new(SorobanOps { /* env, ... */ }));
}
```

---

## References
- Aztec Packages (barretenberg and tooling): https://github.com/AztecProtocol/aztec-packages
- Noir language: https://noir-lang.org/
- Noir compiler (Nargo): https://github.com/noir-lang/noir#nargo

---

## License
**MIT** – see [`LICENSE`](LICENSE) for details.

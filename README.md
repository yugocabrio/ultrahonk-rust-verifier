# UltraHonk Rust Verifier 🦀
Rust verifier library for proofs generated from Noir (UltraHonk) on BN254, with minimal dependencies. Its purpose is to verify Noir/UltraHonk proofs produced by Nargo + barretenberg (bb v0.87.0). A small Noir asset is included only for testing the verifier.

---

## Features
- Verifies proofs generated from Noir (UltraHonk) using Nargo 1.0.0-beta.9 / barretenberg v0.87.0  
- Pure Rust core; `no_std` + `alloc` friendly  
- Supports bb `write_vk --output_format bytes_and_fields` (`vk_fields.json`)  
- Example verification inputs under `circuits/simple_circuit/target` (for tests)

---

## Quick Start
```bash
# Run the verifier test against the included simple circuit
cargo test --features "std"    # quiet

# With tracing output enabled (verbose, for debugging):
cargo test --features "std,trace" -- --nocapture
```

## How It Works
- Typical pipeline: Noir circuit → Nargo prove → bb emits `proof`, `public_inputs`, `vk_fields.json` → this library verifies the proof.
- Test data (already checked in) lives at `circuits/simple_circuit/target` and includes:
  - `proof` (raw bytes)
  - `public_inputs` (raw bytes) or `public_inputs_fields.json`
- `vk_fields.json` (array of hex field elements; bb v0.87.0 layout)
- The test at `tests/verifier_test.rs` loads these files and calls the Rust verifier.

---

## Crate Usage

Add the dependency from a git path or local path. The crate exposes a small API:

```rust
use ultrahonk_rust_verifier::UltraHonkVerifier;

// If you have a vk_fields.json string (bb v0.87.0)
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
- Library scope: verification only (not a prover or circuit compiler). Input files must be produced by Noir/Nargo + bb v0.87.0.
- The verifier internally re-derives the Fiat–Shamir transcript and checks both Sum‑check and Shplonk batch openings over BN254.
- `std` feature enables file I/O and serde JSON; the core logic is `no_std` + `alloc` friendly.
- Enable the `trace` feature to print step-by-step internals for cross‑checking with Solidity outputs.

## Features
- `std`: enables I/O and serde for convenient loading.
- `trace`: prints detailed verifier internals (for debugging); off by default.
- `alloc` (default): required for `no_std` collections.

---

## References
- Aztec Packages (barretenberg and tooling): https://github.com/AztecProtocol/aztec-packages
- Noir language: https://noir-lang.org/
- Noir compiler (Nargo): https://github.com/noir-lang/noir#nargo

---

## License
**MIT** – see [`LICENSE`](LICENSE) for details.

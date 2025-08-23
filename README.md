# UltraHonk Rust Verifier 🦀
A standalone Rust implementation of the **UltraHonk** proof verifier ＋ a handful of sample Noir circuits.

---

## Features
- Pure Rust (`no_std` planned)  
- UltraHonk verifier compatible with Aztec nargo 1.0.0-beta.9 / bb v0.87.x  
- Updated: support for latest bb prove/write_vk (bytes_and_fields)
- Ready-to-run example circuits (`simple_circuit`, `fib_chain`, `poseidon_demo`)

---

## Quick Start
```bash
# 1) Generate proofs & verification keys for all circuits
tests/build_circuits.sh        # downloads nargo & bb v0.82.2 if missing

# 2) Run Rust tests (verifies each proof)
cargo test
````

## How it works (high-level)

1. `tests/build_circuits.sh`

   * installs **Nargo 1.0.0-beta.9** and **bb v0.87.x** if necessary
   * builds each circuit → witness → proof & vk (UltraHonk)
2. Rust tests (`tests/verifier.rs`)

   * load `proof + public_inputs` and `vk_fields.json`
   * call `HonkVerifier::verify()` — all proofs must pass

---

## Roadmap

* [ ] `no_std` verifier for WASM
* [ ] Support Stellar Soroban runtime
* [ ] Publish crate to crates.io

---

## License
**MIT** – see [`LICENSE`](LICENSE) for details.

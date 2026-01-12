Tornado Classic–style Mixer (Soroban + Noir)

Scope
- Deposit stores commitments and rolls an on-chain Poseidon2 Merkle tree (depth 20).
- Withdraw verifies a Noir UltraHonk proof against the stored root and enforces single-use nullifiers.
- Educational sample: no token flow; proof/key artifacts are generated locally.

Layout
- `circuit/`: Noir project + scripts to build proof artifacts (`target/vk`, `target/vk_fields.json`, `proof`, `public_inputs`).
- `contracts/`: Rust tests wiring `UltraHonkVerifierContract` and `MixerContract` in a simulated Soroban environment.

Requirements
- Noir `nargo` 1.0.0-beta.9
- Barretenberg CLI `bb` 0.87.0 with `--oracle_hash keccak`
- Rust stable toolchain (`cargo`)
- Optional Stellar CLI (`stellar-cli`) + Docker if you want to deploy the verifier contract locally

Generate ZK Artifacts
```bash
cd tornado_classic/circuit
scripts/gen_artifacts.sh   # produces target/{vk,proof,public_inputs,…}
```

Run Contract Tests (includes real proof verification)
```bash
cargo test --manifest-path tornado_classic/contracts/Cargo.toml --features testutils -- --nocapture
```
Key checks:
- `deposit` appends to the frontier and updates the on-chain root.
- `withdraw` takes separate `public_inputs` (two 32-byte values ordered `[root, nullifier_hash]`) and a `proof` blob (456 fields); the verifier address is fixed at deploy-time.
- Invalid proofs or double spends fail; root overrides are only exposed in test builds.

Quick Usage Notes
- Deploy `MixerContract` with the verifier contract address in the constructor.
- Normal deposits keep the root up to date automatically.
- Ensure the public inputs match the Poseidon2 tree built off committed leaves.
- This repo is instructional. Production deployments still require token custody design and careful security review.

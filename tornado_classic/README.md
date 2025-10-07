Tornado Classic–style Mixer (Soroban + Noir)

Scope
- Deposit stores commitments and rolls an on-chain Poseidon2 Merkle tree (depth 20).
- Withdraw verifies a Noir UltraHonk proof against the stored root, enforces single-use nullifiers, and emits the verified recipient.
- Educational sample: no token flow, trusted setup, and bn254 precompile missing on Soroban networks (devnet deploy still blocked).

Layout
- `circuit/`: Noir project + scripts to build proof artifacts (`target/vk_fields.json`, `proof`, `public_inputs`).
- `harness/`: Rust tests wiring `UltraHonkVerifierContract` and `MixerContract` in a simulated Soroban environment.

Requirements
- Noir `nargo` 1.0.0-beta.9
- Barretenberg CLI `bb` 0.87.0 with `--oracle_hash keccak`
- Rust stable toolchain (`cargo`)
- Optional Stellar CLI (`stellar-cli`) + Docker if you want to deploy the verifier contract locally

Generate ZK Artifacts
```bash
cd tornado_classic/circuit
scripts/gen_artifacts.sh   # produces target/{vk_fields.json,proof,public_inputs,…}
```

Run Harness Tests (includes real proof verification)
```bash
cargo test --manifest-path tornado_classic/harness/Cargo.toml -- --nocapture
```
Key checks:
- `deposit` appends to the frontier and updates the on-chain root.
- `withdraw_v3` expects packed bytes `[u32_be total_fields][public_inputs][proof]` with public inputs `[nullifier_hash, root, recipient]`.
- Nullifier mismatches or double spends fail; overwriting the root requires a configured admin actor.

Quick Usage Notes
- Call `MixerContract::configure(admin)` once (test harness uses `mock_all_auths`) before any `set_root` overrides; normal deposits keep the root up to date automatically.
- Ensure the public inputs match the Poseidon2 tree built off committed leaves.
- This repo is instructional. For production you need audited hashes, token custody, and a native bn254 verifier.

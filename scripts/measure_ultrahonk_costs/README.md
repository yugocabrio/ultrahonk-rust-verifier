# UltraHonk Cost Measurement

TypeScript utility that simulates UltraHonk contract methods via Soroban RPC and prints CPU instructions, memory usage, and minimum resource fees. The script automatically runs the Rust `preprocess_vk` helper so the verification key matches the on-chain format.

## Prerequisites

- Node.js and npm (`npm install` inside this directory)
- Rust toolchain (`cargo run --manifest-path preprocess_vk_cli/Cargo.toml` is invoked)
- Running Soroban network (local Quickstart/Futurenet)
- Deployed UltraHonk contract
- Dataset containing `vk_fields.json`, `proof`, `public_inputs`

## Usage

```bash
cd scripts/measure_ultrahonk_costs
npm install
npm run measure -- \
  --contract-id <CONTRACT_ID> \
  --source-secret <SECRET_KEY> \
  --rpc-url http://localhost:8000/soroban/rpc \
  --dataset ../../tests/simple_circuit/target
```

Options:

- `--contract-id` – contract to simulate (required)
- `--source-secret` – secret key used to sign requests (required)
- `--rpc-url` – Soroban RPC endpoint (default `http://localhost:8000/soroban/rpc`)
- `--network-passphrase` – network passphrase (default Standalone)
- `--dataset` – dataset directory (default `../../tests/simple_circuit/target`)
- `--skip-verify-with-stored` – omit `verify_proof_with_stored_vk`

The script simulates `set_vk`, `verify_proof`, and—unless skipped—`verify_proof_with_stored_vk`. If `verify_proof_with_stored_vk` fails because no VK is stored, run the invoke helper to call `set_vk` first:

```bash
cd scripts/invoke_ultrahonk
npm run invoke -- set-vk -- --contract-id <CONTRACT_ID> --network local --source-account alice
```

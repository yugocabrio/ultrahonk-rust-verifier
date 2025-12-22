# UltraHonk Cost Measurement

TypeScript utility that simulates UltraHonk contract methods via Soroban RPC and prints CPU instructions, memory usage, and minimum resource fees.

## Prerequisites

- Node.js and npm (`npm install` inside this directory)
- Running Soroban network (local Quickstart/Futurenet)
- Deployed UltraHonk contract
- Dataset containing `vk`, `proof`, `public_inputs`

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

The script simulates `set_vk` followed by `verify_proof` using the dataset’s `public_inputs` and `proof` files. If you want to call `verify_proof_with_stored_vk` yourself, make sure to store a VK first (e.g. via the invoke helper):

```bash
cd scripts/invoke_ultrahonk
npm run invoke -- set-vk -- --contract-id <CONTRACT_ID> --network local --source-account alice
```

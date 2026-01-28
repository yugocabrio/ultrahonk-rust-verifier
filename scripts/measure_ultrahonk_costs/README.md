# UltraHonk Cost Measurement

TypeScript utility that simulates UltraHonk contract methods via Soroban RPC and prints CPU instructions, memory usage, and minimum resource fees.

## Prerequisites

- Node.js and npm (`npm install` inside this directory)
- Running Soroban network (local Quickstart/Futurenet)
- Deployed UltraHonk contract
- Dataset containing `proof`, `public_inputs`

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

The script simulates `verify_proof` using the dataset’s `public_inputs` and `proof` files.
Make sure the contract was deployed with a VK via the constructor first.

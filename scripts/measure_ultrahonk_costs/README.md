# UltraHonk Cost Measurement Scripts

This directory contains scripts to measure the resource costs (CPU, Memory) of the UltraHonk Soroban contract.

## Prerequisites

- Node.js and npm
- A running local Soroban network (standalone)
- A deployed UltraHonk contract

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

## Usage

Run the TypeScript script using `npx ts-node`:

```bash
npx ts-node measure_ultrahonk_costs.ts --contract-id <CONTRACT_ID> --source-secret <SECRET_KEY>
```

### Arguments

- `--contract-id`: The Contract ID of the deployed UltraHonk contract (Required).
- `--source-secret`: The secret key of the account to use for simulation (Default: a hardcoded test key).
- `--rpc-url`: The URL of the Soroban RPC (Default: `http://localhost:8000/soroban/rpc`).
- `--dataset`: Path to the directory containing `vk_fields.json`, `proof`, and `public_inputs` (Default: `../tests/simple_circuit/target`).

### Example

```bash
npx ts-node measure_ultrahonk_costs.ts \
  --contract-id CBLGBJGV67SIQDFPK35SSJQYMYF22HIZ3MAXHOJR44JKEYDTRBYXSCGA \
  --source-secret SBLVSX4PFMIVV5BO3N3DYHA2QKEW4P3JO6WK5WIB36BCAJPJOV57Y3HN
```

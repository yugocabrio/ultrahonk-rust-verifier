# Invoke UltraHonk Script

Helper utility for invoking the UltraHonk verifier contract on Soroban.

## Prerequisites

- Node.js (v18+)
- npm
- `stellar` CLI installed and configured
- A running Soroban network (local, testnet, etc.)

## Setup

```bash
cd scripts/invoke_ultrahonk
npm install
```

## Usage

### Prepare (Pack artifacts and compute proof_id)

```bash
npx ts-node invoke_ultrahonk.ts prepare
```

Options:
- `--dataset <path>`: Directory containing `vk_fields.json`, `public_inputs`, and `proof` (default: `../../tests/simple_circuit/target`)
- `--vk-json <path>`: Override vk_fields.json path
- `--public-inputs <path>`: Override public_inputs path
- `--proof <path>`: Override proof path
- `--output <path>`: Write the packed proof blob to a file
- `--print-base64`: Print proof blob as base64
- `--print-hex`: Print proof blob as hex

Example:
```bash
npx ts-node invoke_ultrahonk.ts prepare --print-hex
```

### Invoke (Call verify_proof on the contract)

```bash
npx ts-node invoke_ultrahonk.ts invoke \
  --contract-id <CONTRACT_ID> \
  --network local \
  --source-account alice
```

Options:
- `--contract-id <id>`: Contract ID to invoke (required)
- `--network <name>`: Network profile (default: `local`)
- `--source-account <name>`: Source account/identity (default: `alice`)
- `--send <yes|no|default>`: Control transaction submission
- `--cost`: Include `--cost` flag when calling stellar CLI
- `--proof-blob-file <path>`: Save the packed proof blob to a file
- `--skip-is-verified`: Skip the follow-up `is_verified` check
- `--dry-run`: Print CLI commands without executing them

Example (dry run):
```bash
npx ts-node invoke_ultrahonk.ts invoke --dry-run
```

Example (real invocation):
```bash
npx ts-node invoke_ultrahonk.ts invoke \
  --contract-id CCJFN27YH2D5HGI5SOZYNYPJZ6W776QCSJSGVIMUZSCEDR52XXLMRSHG \
  --network local \
  --source-account alice \
  --send yes
```

## Output

The script will:
1. Load and pack the proof artifacts
2. Compute the `proof_id` (Keccak-256 hash of the proof blob)
3. Call `verify_proof` on the contract
4. (Optional) Call `is_verified` to confirm the proof was stored

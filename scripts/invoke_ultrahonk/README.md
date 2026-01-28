# Invoke UltraHonk Script

Helper utility for invoking the UltraHonk verifier contract on Soroban.

## Prerequisites

- Node.js (v18+) and npm
- `stellar` CLI installed and configured
- A running Soroban network (local, testnet, etc.)

## Setup

```bash
cd scripts/invoke_ultrahonk
npm install
```

## Usage

### Prepare (Inspect artifacts)

```bash
npx ts-node invoke_ultrahonk.ts prepare
```

Options:
- `--dataset <path>`: Directory containing `public_inputs` and `proof` (default: `../../tests/simple_circuit/target`)
- `--public-inputs <path>`: Override public_inputs path
- `--proof <path>`: Override proof path

### Invoke (Call verify_proof on the contract)

```bash
npx ts-node invoke_ultrahonk.ts invoke \
  --contract-id <CONTRACT_ID> \
  --network local \
  --source-account alice
```

When you run the command above the script will:

1. Load the `public_inputs` and `proof` artifacts.
2. Write the blobs to temporary files and invoke `stellar contract invoke ... -- verify_proof --public_inputs-file-path <inputs> --proof_bytes-file-path <proof>`.

Options:
- `--contract-id <id>`: Contract ID to invoke (required)
- `--network <name>`: Network profile (default: `local`)
- `--source-account <name>`: Source account/identity (default: `alice`)
- `--send <yes|no|default>`: Control transaction submission
- `--cost`: Include `--cost` flag when calling stellar CLI
- `--dry-run`: Print CLI commands without executing them
- `--dataset/...`: Same artifact overrides as `prepare`. You normally only need `--dataset` pointing to the folder containing `public_inputs` and `proof`.

Example (dry run):
```bash
npx ts-node invoke_ultrahonk.ts invoke --dry-run
```

Example (real invocation):
```bash
npx ts-node invoke_ultrahonk.ts invoke \
  --contract-id CDIO5W3SH3BE6DW5HWWUBBOSY52WJKNYX6LWLNRE66SOTVJ524FWAOPO \
  --network local \
  --source-account alice \
  --send yes
```

Note: the contract must be deployed with a VK via the constructor before invoking `verify_proof`.

## Output

The script will:
1. Load the proof artifacts (`public_inputs` and `proof`)
2. Call `verify_proof` on the contract using the `stellar` CLI

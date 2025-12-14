# Invoke UltraHonk Script

Helper utility for invoking the UltraHonk verifier contract on Soroban.

## Prerequisites

- Node.js (v18+) and npm
- `stellar` CLI installed and configured
- A running Soroban network (local, testnet, etc.)
- Rust toolchain (the script shell-outs to `cargo run --manifest-path preprocess_vk_cli/Cargo.toml` from the `ultrahonk_soroban_contract` directory to build the VK bytes)

## Setup

```bash
cd scripts/invoke_ultrahonk
npm install
```

## Usage

### Prepare (Pack artifacts and compute proof hash)

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

When you run the command above the script will:

1. Execute `cargo run --quiet --manifest-path preprocess_vk_cli/Cargo.toml -- <vk_json> <output>` from the `ultrahonk_soroban_contract` directory to convert `vk_fields.json` into the exact byte layout that the Soroban contract expects.  
   ↳ Make sure `cargo` is on your `$PATH`; the helper binary is compiled automatically if it does not exist yet.
2. Pack the proof/public-input artifacts into the `(u32 | inputs | proof)` blob.
3. Write both blobs to temporary files and invoke `stellar contract invoke ... -- verify_proof --vk_bytes-file-path <tmp> --proof_blob-file-path <tmp>`.

Options:
- `--contract-id <id>`: Contract ID to invoke (required)
- `--network <name>`: Network profile (default: `local`)
- `--source-account <name>`: Source account/identity (default: `alice`)
- `--send <yes|no|default>`: Control transaction submission
- `--cost`: Include `--cost` flag when calling stellar CLI
- `--proof-blob-file <path>`: Save the packed proof blob to a file
- `--dry-run`: Print CLI commands without executing them
- `--dataset/--vk-json/...`: Same artifact overrides as `prepare`. You normally only need `--dataset` pointing to the folder containing `vk_fields.json`, `public_inputs`, and `proof`.

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

## Output

The script will:
1. Run the Rust preprocessing helper to derive the verification-key bytes from `vk_fields.json`
2. Load and pack the proof artifacts (including the packed proof blob)
3. Call `verify_proof` on the contract using the `stellar` CLI

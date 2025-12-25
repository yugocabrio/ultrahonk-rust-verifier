# Noir(UltraHonk) Soroban Contract

Soroban contract wrapper around the Noir(UltraHonk) verifier. Inputs are `vk`, `public_inputs`, and `proof`.

## Quickstart (localnet)

Prereqs:
- `stellar` CLI (stellar-cli)
- Rust + `wasm32v1-none` target
- Docker (for localnet)

```bash
# 1) Start localnet
stellar container start -t future --name local --limits unlimited

# 2) Configure network + identity
stellar network add local \
  --rpc-url http://localhost:8000/soroban/rpc \
  --network-passphrase "Standalone Network ; February 2017"
stellar network use local
stellar network health --output json
stellar keys generate --global alice
stellar keys fund alice --network local
stellar keys address alice

# 3) Build + deploy
rustup target add wasm32v1-none
stellar contract build --optimize
stellar contract deploy \
  --wasm target/wasm32v1-none/release/ultrahonk_soroban_contract.wasm \
  --source alice
```

## Invoke verify_proof

### Build ZK artifacts (vk/proof/public_inputs)

From the repo root:

```bash
tests/build_circuits.sh
```

### Use the helper script

Expects a dataset folder with `vk`, `public_inputs`, `proof`:

```bash
cd scripts/invoke_ultrahonk
npm install
npx ts-node invoke_ultrahonk.ts invoke \
  --dataset ../../tests/simple_circuit/target \
  --contract-id <CONTRACT_ID> \
  --network local \
  --source-account alice \
  --send yes
```

### Direct CLI invoke

```bash
stellar contract invoke \
  --id <CONTRACT_ID> \
  --source alice \
  --network local \
  --send yes \
  --cost \
  -- \
  verify_proof \
  --vk_bytes-file-path tests/simple_circuit/target/vk \
  --public_inputs-file-path tests/simple_circuit/target/public_inputs \
  --proof_bytes-file-path tests/simple_circuit/target/proof
```

## Tests

```bash
RUST_TEST_THREADS=1 cargo test --test integration_tests -- --nocapture
cargo test --manifest-path tornado_classic/contracts/Cargo.toml -- --nocapture
```

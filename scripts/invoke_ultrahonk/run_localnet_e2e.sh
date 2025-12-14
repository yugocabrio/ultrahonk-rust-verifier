#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTAINER_NAME="${STELLAR_CONTAINER_NAME:-stellar-local}"
NETWORK_NAME="${STELLAR_NETWORK_NAME:-local}"
SOURCE_ACCOUNT="${STELLAR_SOURCE_ACCOUNT:-alice}"
RPC_URL="${STELLAR_RPC_URL:-http://localhost:8000/soroban/rpc}"
NETWORK_PASSPHRASE="${STELLAR_NETWORK_PASSPHRASE:-Standalone Network ; February 2017}"
DATASET_DIR="${ULTRAHONK_DATASET:-$ROOT_DIR/tests/simple_circuit/target}"

cleanup() {
  stellar container stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Starting Stellar quickstart container..."
stellar container start -t future --name "$CONTAINER_NAME" --limits unlimited

echo "Configuring local network profile..."
stellar network remove "$NETWORK_NAME" >/dev/null 2>&1 || true
stellar network add "$NETWORK_NAME" \
  --rpc-url "$RPC_URL" \
  --network-passphrase "$NETWORK_PASSPHRASE"
stellar network use "$NETWORK_NAME"

echo "Waiting for local network to become healthy..."
for _ in $(seq 1 30); do
  if stellar network health --network "$NETWORK_NAME" --output json >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
stellar network health --network "$NETWORK_NAME" --output json

echo "Preparing source account..."
stellar keys generate "$SOURCE_ACCOUNT" >/dev/null 2>&1 || true
stellar keys fund "$SOURCE_ACCOUNT" --network "$NETWORK_NAME"

echo "Building contract (optimized)..."
stellar contract build --optimize

echo "Deploying contract..."
DEPLOY_OUTPUT=$(stellar contract deploy \
  --wasm "$ROOT_DIR/target/wasm32v1-none/release/ultrahonk_soroban_contract.wasm" \
  --source "$SOURCE_ACCOUNT" \
  --network "$NETWORK_NAME")
echo "$DEPLOY_OUTPUT"
CONTRACT_ID=$(echo "$DEPLOY_OUTPUT" | tail -n 1 | tr -d '[:space:]')
if [[ -z "$CONTRACT_ID" ]]; then
  echo "Failed to parse deployed contract ID" >&2
  exit 1
fi
echo "Deployed contract id: $CONTRACT_ID"

echo "Invoking verify_proof via helper script..."
cd "$ROOT_DIR"
npx ts-node scripts/invoke_ultrahonk/invoke_ultrahonk.ts invoke \
  --dataset "$DATASET_DIR" \
  --contract-id "$CONTRACT_ID" \
  --network "$NETWORK_NAME" \
  --source "$SOURCE_ACCOUNT" \
  --send yes \
  --cost

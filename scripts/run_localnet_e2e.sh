#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
HEALTHY=0
HEALTH_STATUS=""
for attempt in $(seq 1 60); do
  HEALTH_JSON=$(stellar network health --network "$NETWORK_NAME" --output json 2>/dev/null || true)
  if echo "$HEALTH_JSON" | grep -q '"status":"healthy"'; then
    HEALTH_STATUS="$HEALTH_JSON"
    HEALTHY=1
    break
  fi
  echo "  network not ready yet (attempt $attempt), waiting..."
  sleep 5
done
if [[ "$HEALTHY" -ne 1 ]]; then
  echo "Network failed to become healthy in time" >&2
  stellar container logs "$CONTAINER_NAME" | tail -n 200 || true
  exit 1
fi
echo "$HEALTH_STATUS"

echo "Preparing source account..."
stellar keys generate "$SOURCE_ACCOUNT" >/dev/null 2>&1 || true
FUND_OK=0
for attempt in $(seq 1 10); do
  if stellar keys fund "$SOURCE_ACCOUNT" --network "$NETWORK_NAME"; then
    FUND_OK=1
    break
  fi
  echo "  friendbot not ready yet (attempt $attempt), waiting..."
  sleep 5
done
if [[ "$FUND_OK" -ne 1 ]]; then
  echo "Failed to fund $SOURCE_ACCOUNT" >&2
  exit 1
fi

echo "Building contract (optimized)..."
rustup target add wasm32v1-none >/dev/null 2>&1 || true
stellar contract build --optimize

echo "Deploying contract..."
DEPLOY_OUTPUT=$(stellar contract deploy \
  --wasm "$ROOT_DIR/target/wasm32v1-none/release/ultrahonk_soroban_contract.wasm" \
  --source "$SOURCE_ACCOUNT" \
  --network "$NETWORK_NAME" \
  -- \
  --vk_bytes-file-path "$DATASET_DIR/vk")
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

echo "Measuring RPC costs via measurement script..."
SOURCE_SECRET=$(stellar keys secret "$SOURCE_ACCOUNT" | tail -n 1 | tr -d '[:space:]')
pushd "$ROOT_DIR/scripts/measure_ultrahonk_costs" >/dev/null
npm run measure -- \
  --contract-id "$CONTRACT_ID" \
  --source-secret "$SOURCE_SECRET" \
  --rpc-url "$RPC_URL" \
  --dataset "$DATASET_DIR" \
  --network-passphrase "$NETWORK_PASSPHRASE"
popd >/dev/null

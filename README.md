# Ultrahonk Soroban Contract

## How to deploy on Soroban localnet

> Tested against the current docs (Aug 2025). The `soroban` CLI has been consolidated into **`stellar`**. ([developers.stellar.org][1])

---

### 0) Install prerequisites

```bash
# macOS / Linux
brew install stellar-cli

# or (any OS with Rust/cargo)
cargo install --locked stellar-cli
```

Docs: install methods & current version (v23.x). ([developers.stellar.org][1])

Also install Docker Desktop (or another Docker runtime), which the CLI uses to run Quickstart. ([developers.stellar.org][2])

---

### 1) Start localnet with **unlimited** limits

```bash
# Starts Quickstart (stellar-core + RPC + Horizon + Friendbot) in a container
stellar container start local --limits unlimited
```

* The `--limits unlimited` preset sets Soroban resource limits to their maximum values for local mode.
* Quickstart’s local mode exposes RPC on `http://localhost:8000` and includes a Friendbot faucet by default. ([developers.stellar.org][3])

If you ever need to stop it:

```bash
stellar container stop local
```

([developers.stellar.org][4])

---

### 2) Tell the CLI about your **local** network

```bash
# Add a "local" network profile that points at the Quickstart RPC
stellar network add local \
  --rpc-url http://localhost:8000/soroban/rpc \
  --network-passphrase "Standalone Network ; February 2017"

# Make "local" the default network so you can omit --network later
stellar network use local

# Optional: check RPC health
stellar network health --output json
```

* The default passphrase for local mode is exactly: `Standalone Network ; February 2017`. ([developers.stellar.org][3])
* Network management & health commands are in the Stellar CLI manual. ([developers.stellar.org][4])

---

### 3) Create **alice** and auto-fund it (on localnet)

Option A — one step (if your CLI supports generate+fund):

```bash
stellar keys generate --global alice --network local --fund
```

Option B — two steps (works on all recent CLIs):

```bash
# create identity
stellar keys generate --global alice
# fund via Friendbot on localnet
stellar keys fund alice --network local
```

Optional: show alice’s public key and set as default identity

```bash
stellar keys address alice
stellar keys use alice
```

* `keys generate` creates a seed-phrase identity; `keys fund` uses the faucet (Friendbot). ([developers.stellar.org][1])
* Quickstart started via the CLI includes Friendbot, so funding on local works out of the box. ([developers.stellar.org][4])

---

### 4) Build your contract to WASM

If you’re on Rust ≥ 1.85, add the new target:

```bash
rustup target add wasm32v1-none
```

Then build (from your contract crate/workspace):

```bash
stellar contract build
# WASM ends up under target/wasm32v1-none/release/<crate_name>.wasm
```

* `stellar contract build` is the preferred, CLI-wrapped build command.
* Target choice—`wasm32v1-none` vs `wasm32-unknown-unknown`—depends on your Rust version. ([developers.stellar.org][4])

⚠️ Note: Soroban contract Wasm is stored as a ledger entry and may be up to **131,072 bytes (128 KiB)**. In local Quickstart, `--limits unlimited` raises local resource caps (including contract size), so it shouldn’t block deployment; on testnet/pubnet the network’s 128 KiB entry limit still applies. Use `stellar contract optimize` only if you exceed that network limit.

---

### 5) Deploy the contract to localnet

```bash
# Replace <crate_name>.wasm with your actual artifact name
stellar contract deploy \
  --wasm target/wasm32v1-none/release/<crate_name>.wasm \
  --source alice
# prints a contract ID like: C... (save this)
```

That single command uploads the WASM and creates an instance (optionally you can pass constructor args after `--`). ([developers.stellar.org][4])

---

### 6) (Optional) Invoke a method to verify

```bash
# Example shape; adjust --id and args to your contract
stellar contract invoke \
  --id <CONTRACT_ID> \
  --source alice \
  -- \
  --func hello \
  --to "world"
```

(See `stellar contract info interface --id <ID>` to inspect available functions.) ([developers.stellar.org][4])

---

## Troubleshooting (quick fixes)

* **“Failed to find config identity for alice”**
  Create or list identities to confirm it exists, and use the same config scope:

  ```bash
  stellar keys ls
  stellar keys generate --global alice        # if missing
  stellar keys use alice
  ```

  (Ensure you didn’t create `alice` in a project-local `.stellar/identity` but run commands from elsewhere.) ([developers.stellar.org][4])

* **Timeouts / RPC not ready**
  Make sure the container is up and healthy:

  ```bash
  stellar container logs local | tail -n +1
  stellar network health --output json
  ```

  ([developers.stellar.org][4])

* **WASM too big**
  Use the optimizer:

  ```bash
  stellar contract optimize --wasm target/wasm32v1-none/release/<crate_name>.wasm
  ```

  and trim dependencies / features. (The 128 KiB cap still applies.) ([JamesBachini.com][6], [developers.stellar.org][5])

---

## Cheat-sheet (copy/paste)

```bash
# 0) Install CLI (one of)
brew install stellar-cli
# or
cargo install --locked stellar-cli

# 1) Start localnet with unlimited limits
stellar container start local --limits unlimited

# 2) Configure network
stellar network add local \
  --rpc-url http://localhost:8000/soroban/rpc \
  --network-passphrase "Standalone Network ; February 2017"
stellar network use local
stellar network health --output json

# 3) Identity + funding
stellar keys generate --global alice
stellar keys fund alice --network local
stellar keys address alice

# 4) Build
rustup target add wasm32v1-none
stellar contract build

# 5) Deploy
stellar contract deploy --wasm target/wasm32v1-none/release/<crate_name>.wasm --source alice

# 6) Invoke (example)
stellar contract invoke --id <CONTRACT_ID> --source alice -- --func hello --to "world"
```

**References:** official Network Modes / limits, Quickstart getting started, and the Stellar CLI manual for container, network, keys, and contract commands. ([developers.stellar.org][3])

[1]: https://developers.stellar.org/docs/build/smart-contracts/getting-started/setup "Set Up and Configure Your Environment for Writing Smart Contracts | Stellar Docs"
[2]: https://developers.stellar.org/docs/tools/quickstart/getting-started "Getting Started | Stellar Docs"
[3]: https://developers.stellar.org/docs/tools/quickstart/network-modes "Network Modes | Stellar Docs"
[4]: https://developers.stellar.org/docs/tools/cli/stellar-cli "Stellar CLI Manual | Stellar Docs"
[5]: https://developers.stellar.org/docs/build/smart-contracts/getting-started/hello-world?utm_source=chatgpt.com "Hello World - Build Smart Contracts"
[6]: https://jamesbachini.com/building-rust-smart-contracts-on-stellar-soroban/?utm_source=chatgpt.com "Building Rust Smart Contracts On Stellar Soroban"

---

## Invoke script

- See `scripts/invoke_ultrahonk/README.md` for instructions on using the
`invoke_ultrahonk.ts` script to prepare and invoke the Ultrahonk contract.
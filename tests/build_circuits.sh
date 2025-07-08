#!/usr/bin/env bash
set -euo pipefail

NOIR_VERSION="1.0.0-beta.3"
BB_VERSION="v0.82.2"

add_to_ci_path () {
  if [ -n "${GITHUB_PATH:-}" ]; then
    echo "$1" >> "$GITHUB_PATH"
  fi
}

# install noirup
if ! command -v noirup >/dev/null 2>&1; then
  curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
  add_to_ci_path "$HOME/.nargo/bin"
  export PATH="$HOME/.nargo/bin:$PATH"
fi

# install nargo
command -v nargo >/dev/null 2>&1 || NOIR_VERSION="$NOIR_VERSION" noirup

# install bbup
if ! command -v bbup >/dev/null 2>&1; then
  curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
  add_to_ci_path "$HOME/.bb/bin"
  export PATH="$HOME/.bb/bin:$PATH"
fi

# install bb
command -v bb >/dev/null 2>&1 || \
  BB_VERSION="$BB_VERSION" bbup install "$BB_VERSION" --skip-compat-check

# build every circuit ─
for dir in circuits/* ; do
  [ -d "$dir" ] || continue
  name=$(basename "$dir")
  echo "► building $name"

  pushd "$dir" >/dev/null

  ## 1) Prover.toml
  [ -f Prover.toml ] || nargo check --overwrite

  ## 2) witness
  nargo execute

  json="target/${name}.json"
  gz="target/${name}.gz"

  ## 3) proof + public_inputs
  bb prove -b "$json" -w "$gz" -o target \
    --scheme ultra_honk --oracle_hash keccak --output_format bytes_and_fields

  ## 4) vk
  bb write_vk -b "$json" -o target \
    --scheme ultra_honk --oracle_hash keccak --output_format bytes_and_fields

  popd >/dev/null
done

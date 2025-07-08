#!/usr/bin/env bash
set -euo pipefail

NOIR_VERSION="1.0.0-beta.3"
BB_VERSION="v0.82.2"
export PATH="$HOME/.nargo/bin:$HOME/.bb/bin:$PATH"

command -v nargo >/dev/null || {
  curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install \
    | NOIR_VERSION="$NOIR_VERSION" bash
}
command -v bb >/dev/null || {
  curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install \
    | BB_VERSION="$BB_VERSION" bash
}

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

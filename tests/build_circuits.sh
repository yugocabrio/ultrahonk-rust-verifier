#!/usr/bin/env bash
set -euo pipefail

NOIR_VERSION="1.0.0-beta.3"
BB_VERSION="v0.82.2"

add_to_ci_path () {
  [ -n "${GITHUB_PATH:-}" ] && echo "$1" >> "$GITHUB_PATH"
}

# ─── noirup ───
if ! command -v nargo >/dev/null 2>&1; then
  curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
  export PATH="$HOME/.nargo/bin:$PATH"
  add_to_ci_path "$HOME/.nargo/bin"
  NOIR_VERSION="$NOIR_VERSION" noirup
fi

# ─── bbup ───
if ! command -v bb >/dev/null 2>&1; then
  curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
  export PATH="$HOME/.bb/bin:$PATH"
  add_to_ci_path "$HOME/.bb/bin"
  # install bb 本体
  BB_VERSION="$BB_VERSION" "$HOME/.bb/bin/bbup" install "$BB_VERSION" --skip-compat-check
fi

# ─── build every circuit ───
for dir in circuits/* ; do
  [ -d "$dir" ] || continue
  name=$(basename "$dir")
  echo "► building $name"
  pushd "$dir" >/dev/null

  [ -f Prover.toml ] || nargo check --overwrite
  nargo execute

  json="target/${name}.json"
  gz="target/${name}.gz"

  bb prove -b "$json" -w "$gz" -o target \
      --scheme ultra_honk --oracle_hash keccak --output_format bytes_and_fields
  bb write_vk -b "$json" -o target \
      --scheme ultra_honk --oracle_hash keccak --output_format bytes_and_fields

  popd >/dev/null
done

#!/usr/bin/env bash
set -euo pipefail

NOIR_VERSION="1.0.0-beta.9"
BB_VERSION="v0.87.0"

install_nargo() {
  if ! command -v nargo >/dev/null 2>&1; then
    echo "• installing nargo $NOIR_VERSION"
    curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | \
      NOIR_VERSION="$NOIR_VERSION" bash
    export PATH="$HOME/.nargo/bin:$PATH"
    [ -n "${GITHUB_PATH:-}" ] && echo "$HOME/.nargo/bin" >> "$GITHUB_PATH"

    NOIR_VERSION="$NOIR_VERSION" noirup
  fi
}

install_bb() {
  if command -v bb >/dev/null 2>&1; then return; fi

  echo "• installing bb $BB_VERSION"
  mkdir -p "$HOME/.bb/bin"

  # OS / Arch
  uname_s=$(uname -s | tr '[:upper:]' '[:lower:]')
  uname_m=$(uname -m)
  case "${uname_s}_${uname_m}" in
    linux_x86_64)  file="barretenberg-amd64-linux.tar.gz" ;;
    darwin_arm64)  file="barretenberg-arm64-darwin.tar.gz" ;;
    darwin_x86_64) file="barretenberg-amd64-darwin.tar.gz" ;;
    *)             echo "unsupported platform"; exit 1 ;;
  esac

  url="https://github.com/AztecProtocol/aztec-packages/releases/download/${BB_VERSION}/${file}"
  curl -L "$url" -o /tmp/bb.tar.gz
  tar -xzf /tmp/bb.tar.gz -C "$HOME/.bb/bin"
  chmod +x "$HOME/.bb/bin/bb"
  export PATH="$HOME/.bb/bin:$PATH"
  [ -n "${GITHUB_PATH:-}" ] && echo "$HOME/.bb/bin" >> "$GITHUB_PATH"
}

install_nargo
install_bb

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

  bb write_solidity_verifier -s ultra_honk -k target/vk -o target/Verifier.sol

  popd >/dev/null
done

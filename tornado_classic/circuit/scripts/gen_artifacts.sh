#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PROJECT_ROOT}/../.." && pwd)"
export PATH="$HOME/.nargo/bin:$HOME/.bb/bin:${SCRIPT_DIR}:${PATH}"
cd "${PROJECT_ROOT}"

REQUIRED_NARGO_VERSION="1.0.0-beta.9"
REQUIRED_BB_VERSION="v0.87.0"

install_nargo() {
  if ! command -v nargo >/dev/null 2>&1; then
    echo "• installing nargo ${REQUIRED_NARGO_VERSION}"
    curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | \
      NOIR_VERSION="${REQUIRED_NARGO_VERSION}" bash
    noirup -v "${REQUIRED_NARGO_VERSION}"
  fi
}

install_bb() {
  if command -v bb >/dev/null 2>&1; then return; fi

  echo "• installing bb ${REQUIRED_BB_VERSION}"
  mkdir -p "$HOME/.bb/bin"

  uname_s=$(uname -s | tr '[:upper:]' '[:lower:]')
  uname_m=$(uname -m)
  case "${uname_s}_${uname_m}" in
    linux_x86_64)  file="barretenberg-amd64-linux.tar.gz" ;;
    darwin_arm64)  file="barretenberg-arm64-darwin.tar.gz" ;;
    darwin_x86_64) file="barretenberg-amd64-darwin.tar.gz" ;;
    *)             echo "unsupported platform"; exit 1 ;;
  esac

  url="https://github.com/AztecProtocol/aztec-packages/releases/download/${REQUIRED_BB_VERSION}/${file}"
  curl -L "$url" -o /tmp/bb.tar.gz
  tar -xzf /tmp/bb.tar.gz -C "$HOME/.bb/bin"
  chmod +x "$HOME/.bb/bin/bb"
}

install_nargo
install_bb

NARGO_BIN="${NARGO:-$(command -v nargo || echo "${HOME}/.nargo/bin/nargo")}"
BB_BIN="${BB:-$(command -v bb || echo "${HOME}/.bb/bin/bb")}"

PROJECT_NAME="${NAME:-}"
if [[ -z "${PROJECT_NAME}" ]]; then
  if [[ -f Nargo.toml ]]; then
    PROJECT_NAME=$(grep -E '^name\s*=\s*"' Nargo.toml | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')
  fi
fi
PROJECT_NAME=${PROJECT_NAME:-tornado_classic}

echo "[i] Using NARGO='${NARGO_BIN}', BB='${BB_BIN}', NAME='${PROJECT_NAME}'"

if ! command -v "${NARGO_BIN}" >/dev/null 2>&1; then
  echo "[!] nargo not found at ${NARGO_BIN}. Set NARGO=/path/to/nargo" >&2
  exit 1
fi
if [[ ! -x "${BB_BIN}" ]]; then
  echo "[!] bb not found/executable at ${BB_BIN}. Set BB=/path/to/bb" >&2
  exit 1
fi

NARGO_VERSION_RAW="$(${NARGO_BIN} --version 2>/dev/null | head -n1)"
if [[ "${NARGO_VERSION_RAW}" != *"${REQUIRED_NARGO_VERSION}"* ]]; then
  echo "[!] Expected nargo ${REQUIRED_NARGO_VERSION}, but got '${NARGO_VERSION_RAW}'" >&2
  exit 1
fi

BB_VERSION_RAW="$(${BB_BIN} --version 2>/dev/null | head -n1)"
if [[ "${BB_VERSION_RAW}" != "${REQUIRED_BB_VERSION}" && "v${BB_VERSION_RAW}" != "${REQUIRED_BB_VERSION}" ]]; then
  echo "[!] Expected bb ${REQUIRED_BB_VERSION}, but got '${BB_VERSION_RAW}'" >&2
  exit 1
fi

echo "[1/4] nargo compile"
"${NARGO_BIN}" compile

if [[ "${GENERATE_PROVER:-1}" != "0" ]]; then
  echo "[i] Generating Prover.toml inputs (seed=${TORNADO_SEED:-1})"
  (cd "${REPO_ROOT}" && TORNADO_GENERATE=1 TORNADO_SEED="${TORNADO_SEED:-1}" \
    cargo run --example populate_publics --manifest-path tornado_classic/contracts/Cargo.toml --features std)
fi

echo "[2/4] nargo execute (solve witness)"
"${NARGO_BIN}" execute

ACIR="target/${PROJECT_NAME}.json"
WIT="target/${PROJECT_NAME}.gz"
if [[ ! -f "${ACIR}" ]]; then
  echo "[!] ACIR not found: ${ACIR}" >&2
  ls -la target || true
  exit 1
fi
if [[ ! -f "${WIT}" ]]; then
  echo "[!] Witness not found: ${WIT}" >&2
  ls -la target || true
  exit 1
fi

echo "[3/4] bb write_vk --scheme ultra_honk --oracle_hash keccak"
rm -rf target/vk_fields.json target/vk
"${BB_BIN}" write_vk \
  --scheme ultra_honk \
  --oracle_hash keccak \
  --bytecode_path "${ACIR}" \
  --output_format bytes_and_fields \
  --output_path target

# bb may write directories; flatten to files.
if [[ -d target/vk_fields.json && -f target/vk_fields.json/vk_fields.json ]]; then
  mv target/vk_fields.json/vk_fields.json target/vk_fields.json.tmp
  rmdir target/vk_fields.json
  mv target/vk_fields.json.tmp target/vk_fields.json
fi
if [[ -d target/vk && -f target/vk/vk ]]; then
  mv target/vk/vk target/vk.tmp
  rmdir target/vk
  mv target/vk.tmp target/vk
fi

echo "[4/4] bb prove --scheme ultra_honk --oracle_hash keccak --output_format bytes_and_fields"
"${BB_BIN}" prove \
  --scheme ultra_honk \
  --oracle_hash keccak \
  --bytecode_path "${ACIR}" \
  --witness_path "${WIT}" \
  --output_format bytes_and_fields \
  --output_path target

echo "[ok] Artifacts generated under ./target:"
ls -la target | sed 's/^/  /'

echo "\nUsage next:"
echo "  - Harness verifier test reads:"
echo "      circuit/target/vk_fields.json"
echo "      circuit/target/proof"
echo "      circuit/target/public_inputs"
echo "  - Then run: cargo test --manifest-path tornado_classic/contracts/Cargo.toml -- tests::verify_tornado_classic_proof_succeeds --nocapture"

echo "\nProof/public inputs for external verifiers:"
echo "  - Proof (hex):"
echo -n "    0x"; cat target/proof | od -An -v -t x1 | tr -d $' \n'; echo
echo "  - Public inputs (bytes32[]):"
if [[ -f target/public_inputs_fields.json ]]; then
  sed 's/^/    /' target/public_inputs_fields.json
else
  echo "    target/public_inputs_fields.json not found"
fi

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
export PATH="${SCRIPT_DIR}:${PATH}"
cd "${PROJECT_ROOT}"

NARGO_BIN="${NARGO:-${HOME}/.nargo/bin/nargo}"
BB_BIN="${BB:-${HOME}/.bb/bb}"
REQUIRED_NARGO_VERSION="1.0.0-beta.9"
REQUIRED_BB_VERSION="v0.87.0"

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
if [[ "${BB_VERSION_RAW}" != "${REQUIRED_BB_VERSION}" ]]; then
  echo "[!] Expected bb ${REQUIRED_BB_VERSION}, but got '${BB_VERSION_RAW}'" >&2
  exit 1
fi

echo "[1/4] nargo compile"
"${NARGO_BIN}" compile

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
if [[ -f target/vk_fields.json ]]; then
  rm -f target/vk_fields.json
fi
if [[ -d target/vk_fields.json ]]; then
  rm -rf target/vk_fields.json
fi
"${BB_BIN}" write_vk \
  --scheme ultra_honk \
  --oracle_hash keccak \
  --bytecode_path "${ACIR}" \
  --output_format fields \
  --output_path target/vk_fields.json

# bb currently writes a directory containing vk_fields.json; flatten to a single file.
if [[ -d target/vk_fields.json && -f target/vk_fields.json/vk_fields.json ]]; then
  mv target/vk_fields.json/vk_fields.json target/vk_fields.json.tmp
  rmdir target/vk_fields.json
  mv target/vk_fields.json.tmp target/vk_fields.json
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
echo "  - Then run: cargo test --manifest-path tornado_classic/harness/Cargo.toml -- tests::verify_tornado_classic_proof_succeeds --nocapture"

echo "\nProof/public inputs for external verifiers:"
echo "  - Proof (hex):"
echo -n "    0x"; cat target/proof | od -An -v -t x1 | tr -d $' \n'; echo
echo "  - Public inputs (bytes32[]):"
if [[ -f target/public_inputs_fields.json ]]; then
  sed 's/^/    /' target/public_inputs_fields.json
else
  echo "    target/public_inputs_fields.json not found"
fi

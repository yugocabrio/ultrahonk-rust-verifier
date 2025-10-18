#!/usr/bin/env python3
"""
Helper utilities for invoking the UltraHonk verifier contract.

The contract expects two byte arguments:
  1. vk_json    → raw contents of `vk_fields.json`
  2. proof_blob → (u32_be total_fields) || public_inputs || proof

This script can:
  * pack the fib_chain (or other) artifacts into the expected blob format
  * compute the proof_id (Keccak-256 of the packed proof blob)
  * drive the `stellar contract invoke` CLI for verify_proof + is_verified

Example (local Quickstart):
    python scripts/invoke_ultrahonk.py invoke \
        --dataset tests/fib_chain/target \
        --contract-id CD6HGS5V7XJPSPJ5HHPHUZXLYGZAJJC3L6QWR4YZG4NIRO65UYQ6KIYP \
        --network local --source-account alice --send no
"""

from __future__ import annotations

import argparse
import base64
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence


DEFAULT_CONTRACT_ID = "CD6HGS5V7XJPSPJ5HHPHUZXLYGZAJJC3L6QWR4YZG4NIRO65UYQ6KIYP"
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET_DIR = (REPO_ROOT / "tests" / "fib_chain" / "target").resolve()


# === Minimal Keccak-256 implementation (no external deps) ====================
_ROTATION_OFFSETS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

_ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)

_U64_MASK = (1 << 64) - 1


def _rotl64(value: int, shift: int) -> int:
    shift %= 64
    if shift == 0:
        return value & _U64_MASK
    return ((value << shift) & _U64_MASK) | (value >> (64 - shift))


def _keccak_f1600(state: list[int]) -> None:
    assert len(state) == 25
    for rc in _ROUND_CONSTANTS:
        # θ step
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for i in range(25):
            state[i] ^= d[i % 5]

        # ρ and π steps combined
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                idx = x + 5 * y
                new_x = y
                new_y = (2 * x + 3 * y) % 5
                b[new_x + 5 * new_y] = _rotl64(state[idx], _ROTATION_OFFSETS[x][y])

        # χ step
        for x in range(5):
            for y in range(5):
                idx = x + 5 * y
                state[idx] = b[idx] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])

        # ι step
        state[0] ^= rc
        state[0] &= _U64_MASK


def keccak256(data: bytes) -> bytes:
    rate_bytes = 136  # 1088-bit rate
    state = [0] * 25

    # Absorb full blocks
    offset = 0
    while offset + rate_bytes <= len(data):
        block = data[offset : offset + rate_bytes]
        for i in range(rate_bytes // 8):
            lane = int.from_bytes(block[i * 8 : (i + 1) * 8], "little")
            state[i] ^= lane
        _keccak_f1600(state)
        offset += rate_bytes

    # Last block with padding (Keccak pad10*1 with domain 0x01)
    remaining = data[offset:]
    block = bytearray(rate_bytes)
    block[: len(remaining)] = remaining
    block[len(remaining)] ^= 0x01
    block[-1] ^= 0x80

    for i in range(rate_bytes // 8):
        lane = int.from_bytes(block[i * 8 : (i + 1) * 8], "little")
        state[i] ^= lane
    _keccak_f1600(state)

    # Squeeze output
    out = bytearray()
    while len(out) < 32:
        for i in range(rate_bytes // 8):
            out.extend(state[i].to_bytes(8, "little"))
        if len(out) >= 32:
            break
        _keccak_f1600(state)
    return bytes(out[:32])


# === Data loading / packing ==================================================
@dataclass
class PackedArtifacts:
    vk_json_path: Path
    vk_bytes: bytes
    public_inputs_bytes: bytes
    proof_bytes: bytes

    @property
    def proof_fields(self) -> int:
        if len(self.proof_bytes) % 32 != 0:
            raise ValueError("Proof blob is not a multiple of 32 bytes.")
        return len(self.proof_bytes) // 32

    @property
    def public_input_fields(self) -> int:
        if len(self.public_inputs_bytes) % 32 != 0:
            raise ValueError("Public inputs are not a multiple of 32 bytes.")
        return len(self.public_inputs_bytes) // 32

    def build_proof_blob(self) -> bytes:
        total_fields = self.proof_fields + self.public_input_fields
        header = total_fields.to_bytes(4, "big")
        return header + self.public_inputs_bytes + self.proof_bytes


def load_artifacts(
    dataset: Optional[Path],
    vk_json: Optional[Path],
    public_inputs: Optional[Path],
    proof: Optional[Path],
) -> PackedArtifacts:
    if dataset is None:
        dataset = DEFAULT_DATASET_DIR
    else:
        dataset = dataset.expanduser()
        if not dataset.is_absolute():
            dataset = (Path.cwd() / dataset).resolve()

    vk_json = (vk_json.expanduser() if vk_json else dataset / "vk_fields.json")
    public_inputs = (
        public_inputs.expanduser() if public_inputs else dataset / "public_inputs"
    )
    proof = proof.expanduser() if proof else dataset / "proof"

    vk_json_path = Path(vk_json).resolve()
    public_inputs_path = Path(public_inputs).resolve()
    proof_path = Path(proof).resolve()

    if not vk_json_path.exists():
        raise FileNotFoundError(f"vk JSON not found: {vk_json_path}")
    if not public_inputs_path.exists():
        raise FileNotFoundError(f"public inputs not found: {public_inputs_path}")
    if not proof_path.exists():
        raise FileNotFoundError(f"proof not found: {proof_path}")

    return PackedArtifacts(
        vk_json_path=vk_json_path,
        vk_bytes=vk_json_path.read_bytes(),
        public_inputs_bytes=public_inputs_path.read_bytes(),
        proof_bytes=proof_path.read_bytes(),
    )


# === CLI helpers =============================================================
def run_command(cmd: Sequence[str], dry_run: bool) -> int:
    display_parts: list[str] = []
    for part in cmd:
        if len(part) > 128:
            display_parts.append(f"<{len(part)} chars>")
        else:
            display_parts.append(part)
    print("→", " ".join(display_parts))
    if dry_run:
        return 0
    proc = subprocess.run(cmd)
    return proc.returncode


def print_summary(artifacts: PackedArtifacts, proof_blob: bytes, proof_id: bytes) -> None:
    print("vk_json:", artifacts.vk_json_path)
    print("public inputs bytes:", len(artifacts.public_inputs_bytes))
    print("proof bytes:", len(artifacts.proof_bytes))
    print("proof fields:", artifacts.proof_fields)
    print("public input fields:", artifacts.public_input_fields)
    print("total fields:", artifacts.proof_fields + artifacts.public_input_fields)
    print("proof blob bytes:", len(proof_blob))
    print("proof_id (hex):", proof_id.hex())
    print("proof_id (base64):", base64.b64encode(proof_id).decode("ascii"))


def command_prepare(args: argparse.Namespace) -> int:
    try:
        artifacts = load_artifacts(args.dataset, args.vk_json, args.public_inputs, args.proof)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    proof_blob = artifacts.build_proof_blob()
    proof_id = keccak256(proof_blob)

    print_summary(artifacts, proof_blob, proof_id)

    if args.output:
        out_path = Path(args.output).expanduser()
        out_path.write_bytes(proof_blob)
        print(f"Wrote proof blob to {out_path}")

    if args.print_base64:
        print("proof_blob (base64):", base64.b64encode(proof_blob).decode("ascii"))
    if args.print_hex:
        print("proof_blob (hex):", proof_blob.hex())

    return 0


def command_invoke(args: argparse.Namespace) -> int:
    try:
        artifacts = load_artifacts(args.dataset, args.vk_json, args.public_inputs, args.proof)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    proof_blob = artifacts.build_proof_blob()
    proof_id = keccak256(proof_blob)
    print_summary(artifacts, proof_blob, proof_id)

    if args.proof_blob_file:
        out_path = Path(args.proof_blob_file).expanduser()
        out_path.write_bytes(proof_blob)
        print(f"Wrote proof blob to {out_path}")

    vk_hex = artifacts.vk_bytes.hex()
    proof_hex = proof_blob.hex()

    verify_cmd: list[str] = [
        "stellar",
        "contract",
        "invoke",
        "--id",
        args.contract_id,
        "--source-account",
        args.source,
        "--network",
        args.network,
    ]
    if args.send != "default":
        verify_cmd.extend(["--send", args.send])
    if args.cost:
        verify_cmd.append("--cost")
    verify_cmd.extend(
        [
            "--",
            "verify_proof",
            "--vk-json",
            vk_hex,
            "--proof-blob",
            proof_hex,
        ]
    )

    rc = run_command(verify_cmd, args.dry_run)
    if rc != 0:
        return rc

    if not args.skip_is_verified:
        proof_id_hex = proof_id.hex()
        check_cmd: list[str] = [
            "stellar",
            "contract",
            "invoke",
            "--id",
            args.contract_id,
            "--source-account",
            args.source,
            "--network",
            args.network,
        ]
        if args.send != "default":
            check_cmd.extend(["--send", args.send])
        if args.cost:
            check_cmd.append("--cost")
        check_cmd.extend(
            [
                "--",
                "is_verified",
                "--proof-id",
                proof_id_hex,
            ]
        )
        rc = run_command(check_cmd, args.dry_run)
        if rc != 0:
            return rc

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Invoke UltraHonk verifier contract.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_artifact_args(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--dataset",
            type=Path,
            help=(
                "Directory containing vk_fields.json, public_inputs, and proof. "
                f"Defaults to {DEFAULT_DATASET_DIR}"
            ),
            default=None,
        )
        p.add_argument("--vk-json", type=Path, help="Override vk_fields.json path.")
        p.add_argument("--public-inputs", type=Path, help="Override public_inputs path.")
        p.add_argument("--proof", type=Path, help="Override proof path.")

    prepare = subparsers.add_parser("prepare", help="Pack artifacts and print proof blob/proof id.")
    add_artifact_args(prepare)
    prepare.add_argument("--output", type=Path, help="Optional file to write the packed proof blob.")
    prepare.add_argument("--print-base64", action="store_true", help="Print proof blob as base64.")
    prepare.add_argument("--print-hex", action="store_true", help="Print proof blob as hex.")
    prepare.set_defaults(func=command_prepare)

    invoke = subparsers.add_parser("invoke", help="Invoke verify_proof (and optionally is_verified).")
    add_artifact_args(invoke)
    invoke.add_argument("--contract-id", default=DEFAULT_CONTRACT_ID, help="Contract ID to invoke.")
    invoke.add_argument("--network", default="local", help="Network profile or RPC alias (default: local).")
    invoke.add_argument(
        "--source-account",
        "--source",
        dest="source",
        default="alice",
        help="Source account/identity for the transaction (default: alice).",
    )
    invoke.add_argument(
        "--send",
        default="default",
        choices=["default", "no", "yes"],
        help="Forward to `stellar contract invoke --send` (default behavior matches CLI default).",
    )
    invoke.add_argument("--cost", action="store_true", help="Include `--cost` when calling stellar CLI.")
    invoke.add_argument(
        "--proof-blob-file",
        type=Path,
        help="Write packed proof blob to this path and reuse it instead of a temporary file.",
    )
    invoke.add_argument(
        "--skip-is-verified",
        action="store_true",
        help="Do not perform the follow-up is_verified check.",
    )
    invoke.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the CLI commands instead of executing them.",
    )
    invoke.set_defaults(func=command_invoke)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

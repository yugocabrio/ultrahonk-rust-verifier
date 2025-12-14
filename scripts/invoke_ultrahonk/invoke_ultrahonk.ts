#!/usr/bin/env ts-node
/**
 * Helper utilities for invoking the UltraHonk verifier contract.
 *
 * The contract expects two byte arguments:
 *   1. vk_json    → raw contents of `vk_fields.json`
 *   2. proof_blob → (u32_be total_fields) || public_inputs || proof
 *
 * This script can:
 *   * pack the simple_circuit (or other) artifacts into the expected blob format
 *   * drive the `stellar contract invoke` CLI for verify_proof
 *
 * Example (local Quickstart):
 *     npx ts-node invoke_ultrahonk.ts invoke \
 *         --dataset ../../tests/simple_circuit/target \
 *         --contract-id CCJFN27YH2D5HGI5SOZYNYPJZ6W776QCSJSGVIMUZSCEDR52XXLMRSHG \
 *         --network local --source-account alice --send yes
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { spawn, spawnSync } from 'child_process';
import { ArgumentParser } from 'argparse';

// === Constants ===============================================================

const DEFAULT_CONTRACT_ID = 'CD6HGS5V7XJPSPJ5HHPHUZXLYGZAJJC3L6QWR4YZG4NIRO65UYQ6KIYP';
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const PREPROCESS_MANIFEST = path.resolve(REPO_ROOT, 'preprocess_vk_cli', 'Cargo.toml');
const DEFAULT_DATASET_DIR = path.resolve(REPO_ROOT, 'tests', 'simple_circuit', 'target');

// === Minimal Keccak-256 implementation (no external deps) ====================

const ROTATION_OFFSETS: number[][] = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

const ROUND_CONSTANTS: bigint[] = [
  0x0000000000000001n,
  0x0000000000008082n,
  0x800000000000808an,
  0x8000000080008000n,
  0x000000000000808bn,
  0x0000000080000001n,
  0x8000000080008081n,
  0x8000000000008009n,
  0x000000000000008an,
  0x0000000000000088n,
  0x0000000080008009n,
  0x000000008000000an,
  0x000000008000808bn,
  0x800000000000008bn,
  0x8000000000008089n,
  0x8000000000008003n,
  0x8000000000008002n,
  0x8000000000000080n,
  0x000000000000800an,
  0x800000008000000an,
  0x8000000080008081n,
  0x8000000000008080n,
  0x0000000080000001n,
  0x8000000080008008n,
];

const U64_MASK = (1n << 64n) - 1n;

function rotl64(value: bigint, shift: number): bigint {
  shift = shift % 64;
  if (shift === 0) return value & U64_MASK;
  return ((value << BigInt(shift)) & U64_MASK) | (value >> BigInt(64 - shift));
}

function keccakF1600(state: bigint[]): void {
  for (const rc of ROUND_CONSTANTS) {
    // θ step
    const c: bigint[] = [];
    for (let x = 0; x < 5; x++) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    const d: bigint[] = [];
    for (let x = 0; x < 5; x++) {
      d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
    }
    for (let i = 0; i < 25; i++) {
      state[i] ^= d[i % 5];
    }

    // ρ and π steps combined
    const b: bigint[] = new Array(25).fill(0n);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const idx = x + 5 * y;
        const newX = y;
        const newY = (2 * x + 3 * y) % 5;
        b[newX + 5 * newY] = rotl64(state[idx], ROTATION_OFFSETS[x][y]);
      }
    }

    // χ step
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const idx = x + 5 * y;
        state[idx] = b[idx] ^ ((~b[(x + 1) % 5 + 5 * y] & U64_MASK) & b[(x + 2) % 5 + 5 * y]);
      }
    }

    // ι step
    state[0] ^= rc;
    state[0] &= U64_MASK;
  }
}

function keccak256(data: Buffer): Buffer {
  const rateBytes = 136; // 1088-bit rate
  const state: bigint[] = new Array(25).fill(0n);

  // Absorb full blocks
  let offset = 0;
  while (offset + rateBytes <= data.length) {
    const block = data.subarray(offset, offset + rateBytes);
    for (let i = 0; i < rateBytes / 8; i++) {
      const lane = block.readBigUInt64LE(i * 8);
      state[i] ^= lane;
    }
    keccakF1600(state);
    offset += rateBytes;
  }

  // Last block with padding (Keccak pad10*1 with domain 0x01)
  const remaining = data.subarray(offset);
  const block = Buffer.alloc(rateBytes);
  remaining.copy(block);
  block[remaining.length] ^= 0x01;
  block[rateBytes - 1] ^= 0x80;

  for (let i = 0; i < rateBytes / 8; i++) {
    const lane = block.readBigUInt64LE(i * 8);
    state[i] ^= lane;
  }
  keccakF1600(state);

  // Squeeze output
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) {
    out.writeBigUInt64LE(state[i], i * 8);
  }
  return out;
}

// === Data loading / packing ==================================================

interface PackedArtifacts {
  vkJsonPath: string;
  vkBytes: Buffer;
  publicInputsBytes: Buffer;
  proofBytes: Buffer;
}

function preprocessVkBytes(vkJsonPath: string): Buffer {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'preprocess-vk-'));
  const outPath = path.join(tmpDir, 'vk.bin');
  try {
    const result = spawnSync(
      'cargo',
      ['run', '--quiet', '--manifest-path', PREPROCESS_MANIFEST, '--', vkJsonPath, outPath],
      { stdio: 'inherit' }
    );
    if (result.status !== 0) {
      throw new Error('preprocess_vk failed');
    }
    return fs.readFileSync(outPath);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function getProofFields(artifacts: PackedArtifacts): number {
  if (artifacts.proofBytes.length % 32 !== 0) {
    throw new Error('Proof blob is not a multiple of 32 bytes.');
  }
  return artifacts.proofBytes.length / 32;
}

function getPublicInputFields(artifacts: PackedArtifacts): number {
  if (artifacts.publicInputsBytes.length % 32 !== 0) {
    throw new Error('Public inputs are not a multiple of 32 bytes.');
  }
  return artifacts.publicInputsBytes.length / 32;
}

function buildProofBlob(artifacts: PackedArtifacts): Buffer {
  const proofFields = getProofFields(artifacts);
  const publicInputFields = getPublicInputFields(artifacts);
  const totalFields = proofFields + publicInputFields;
  const header = Buffer.alloc(4);
  header.writeUInt32BE(totalFields, 0);
  return Buffer.concat([header, artifacts.publicInputsBytes, artifacts.proofBytes]);
}

function loadArtifacts(
  dataset: string | null,
  vkJson: string | null,
  publicInputs: string | null,
  proof: string | null
): PackedArtifacts {
  let datasetDir = dataset ?? DEFAULT_DATASET_DIR;
  if (!path.isAbsolute(datasetDir)) {
    datasetDir = path.resolve(process.cwd(), datasetDir);
  }

  const vkJsonPath = vkJson ?? path.join(datasetDir, 'vk_fields.json');
  const publicInputsPath = publicInputs ?? path.join(datasetDir, 'public_inputs');
  const proofPath = proof ?? path.join(datasetDir, 'proof');

  const resolvedVkJson = path.resolve(vkJsonPath);
  const resolvedPublicInputs = path.resolve(publicInputsPath);
  const resolvedProof = path.resolve(proofPath);

  if (!fs.existsSync(resolvedVkJson)) {
    throw new Error(`vk JSON not found: ${resolvedVkJson}`);
  }
  if (!fs.existsSync(resolvedPublicInputs)) {
    throw new Error(`public inputs not found: ${resolvedPublicInputs}`);
  }
  if (!fs.existsSync(resolvedProof)) {
    throw new Error(`proof not found: ${resolvedProof}`);
  }

  return {
    vkJsonPath: resolvedVkJson,
    vkBytes: preprocessVkBytes(resolvedVkJson),
    publicInputsBytes: fs.readFileSync(resolvedPublicInputs),
    proofBytes: fs.readFileSync(resolvedProof),
  };
}

// === CLI helpers =============================================================

interface CommandResult {
  returncode: number;
  stdout: string;
  stderr: string;
}

function getCliVariants(functionName: string): string[] {
  const variants = [functionName];
  const hyphenated = functionName.replace(/_/g, '-');
  if (!variants.includes(hyphenated)) {
    variants.push(hyphenated);
  }
  return variants;
}

function runCommand(cmd: string[], dryRun: boolean): Promise<CommandResult> {
  const displayParts: string[] = cmd.map((part) =>
    part.length > 128 ? `<${part.length} chars>` : part
  );
  console.log('→', displayParts.join(' '));

  if (dryRun) {
    return Promise.resolve({ returncode: 0, stdout: '', stderr: '' });
  }

  return new Promise((resolve) => {
    const proc = spawn(cmd[0], cmd.slice(1), {
      stdio: ['inherit', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    proc.stdout?.on('data', (data: Buffer) => {
      const text = data.toString();
      stdout += text;
      process.stdout.write(text);
    });

    proc.stderr?.on('data', (data: Buffer) => {
      const text = data.toString();
      stderr += text;
      process.stderr.write(text);
    });

    proc.on('close', (code) => {
      resolve({ returncode: code ?? 1, stdout, stderr });
    });

    proc.on('error', (err) => {
      stderr += err.message;
      resolve({ returncode: 1, stdout, stderr });
    });
  });
}

async function invokeWithVariants(
  baseCmd: string[],
  functionName: string,
  args: string[],
  dryRun: boolean
): Promise<CommandResult> {
  const variants = getCliVariants(functionName);
  let lastResult: CommandResult | null = null;

  for (let idx = 0; idx < variants.length; idx++) {
    const cliName = variants[idx];
    const cmd = [...baseCmd, '--', cliName, ...args];
    const result = await runCommand(cmd, dryRun);
    if (dryRun || result.returncode === 0) {
      return result;
    }
    const combined = (result.stderr + '\n' + result.stdout).toLowerCase();
    if (
      (combined.includes('unrecognized subcommand') ||
        combined.includes('unexpected argument')) &&
      idx + 1 < variants.length
    ) {
      lastResult = result;
      continue;
    }
    return result;
  }

  return lastResult ?? { returncode: 1, stdout: '', stderr: '' };
}

// === Commands ================================================================

function printSummary(artifacts: PackedArtifacts, proofBlob: Buffer): void {
  console.log('vk_json:', artifacts.vkJsonPath);
  console.log('public inputs bytes:', artifacts.publicInputsBytes.length);
  console.log('proof bytes:', artifacts.proofBytes.length);
  console.log('proof fields:', getProofFields(artifacts));
  console.log('public input fields:', getPublicInputFields(artifacts));
  console.log('total fields:', getProofFields(artifacts) + getPublicInputFields(artifacts));
  console.log('proof blob bytes:', proofBlob.length);
}

async function commandPrepare(args: any): Promise<number> {
  try {
    const artifacts = loadArtifacts(
      args.dataset,
      args.vk_json,
      args.public_inputs,
      args.proof
    );
    const proofBlob = buildProofBlob(artifacts);
    printSummary(artifacts, proofBlob);

    if (args.output) {
      const outPath = path.resolve(args.output);
      fs.writeFileSync(outPath, proofBlob);
      console.log(`Wrote proof blob to ${outPath}`);
    }

    if (args.print_base64) {
      console.log('proof_blob (base64):', proofBlob.toString('base64'));
    }
    if (args.print_hex) {
      console.log('proof_blob (hex):', proofBlob.toString('hex'));
    }

    return 0;
  } catch (exc: any) {
    console.error(`error: ${exc.message}`);
    return 1;
  }
}

async function commandInvoke(args: any): Promise<number> {
  try {
    const artifacts = loadArtifacts(
      args.dataset,
      args.vk_json,
      args.public_inputs,
      args.proof
    );
    const proofBlob = buildProofBlob(artifacts);
    printSummary(artifacts, proofBlob);

    if (args.proof_blob_file) {
      const outPath = path.resolve(args.proof_blob_file);
      fs.writeFileSync(outPath, proofBlob);
      console.log(`Wrote proof blob to ${outPath}`);
    }

    const baseCmd: string[] = [
      'stellar',
      'contract',
      'invoke',
      '--id',
      args.contract_id,
      '--source-account',
      args.source,
      '--network',
      args.network,
    ];
    if (args.send !== 'default') {
      baseCmd.push('--send', args.send);
    }
    if (args.cost) {
      baseCmd.push('--cost');
    }

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ultrahonk-'));
    try {
      const vkFile = path.join(tmpDir, 'vk.bin');
      const proofFile = path.join(tmpDir, 'proof_blob.bin');
      fs.writeFileSync(vkFile, artifacts.vkBytes);
      fs.writeFileSync(proofFile, proofBlob);

      const verifyArgs = [
        '--vk_bytes-file-path',
        vkFile,
        '--proof_blob-file-path',
        proofFile,
      ];
      const result = await invokeWithVariants(baseCmd, 'verify_proof', verifyArgs, args.dry_run);
      if (result.returncode !== 0) {
        return result.returncode;
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }

    return 0;
  } catch (exc: any) {
    console.error(`error: ${exc.message}`);
    return 1;
  }
}

async function commandSetVk(args: any): Promise<number> {
  try {
    const artifacts = loadArtifacts(
      args.dataset,
      args.vk_json,
      args.public_inputs,
      args.proof
    );

    console.log('vk_json:', artifacts.vkJsonPath);
    const baseCmd: string[] = [
      'stellar',
      'contract',
      'invoke',
      '--id',
      args.contract_id,
      '--source-account',
      args.source,
      '--network',
      args.network,
    ];
    if (args.send !== 'default') {
      baseCmd.push('--send', args.send);
    }
    if (args.cost) {
      baseCmd.push('--cost');
    }

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ultrahonk-'));
    try {
      const vkFile = path.join(tmpDir, 'vk.bin');
      fs.writeFileSync(vkFile, artifacts.vkBytes);
      const setVkArgs = ['--vk_bytes-file-path', vkFile];
      const result = await invokeWithVariants(baseCmd, 'set_vk', setVkArgs, args.dry_run);
      return result.returncode;
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  } catch (exc: any) {
    console.error(`error: ${exc.message}`);
    return 1;
  }
}

// === Main ====================================================================

function buildParser(): ArgumentParser {
  const parser = new ArgumentParser({
    description: 'Invoke UltraHonk verifier contract.',
  });

  const subparsers = parser.add_subparsers({
    dest: 'command',
    required: true,
  });

  const addArtifactArgs = (p: ArgumentParser): void => {
    p.add_argument('--dataset', {
      type: 'str',
      help: `Directory containing vk_fields.json, public_inputs, and proof. Defaults to ${DEFAULT_DATASET_DIR}`,
      default: null,
    });
    p.add_argument('--vk-json', {
      type: 'str',
      help: 'Override vk_fields.json path.',
      default: null,
    });
    p.add_argument('--public-inputs', {
      type: 'str',
      help: 'Override public_inputs path.',
      default: null,
    });
    p.add_argument('--proof', {
      type: 'str',
      help: 'Override proof path.',
      default: null,
    });
  };

  const prepare = subparsers.add_parser('prepare', {
    help: 'Pack artifacts and print proof blob/proof id.',
  });
  addArtifactArgs(prepare);
  prepare.add_argument('--output', {
    type: 'str',
    help: 'Optional file to write the packed proof blob.',
    default: null,
  });
  prepare.add_argument('--print-base64', {
    action: 'store_true',
    help: 'Print proof blob as base64.',
  });
  prepare.add_argument('--print-hex', {
    action: 'store_true',
    help: 'Print proof blob as hex.',
  });

  const invoke = subparsers.add_parser('invoke', {
    help: 'Invoke verify_proof on the contract.',
  });
  addArtifactArgs(invoke);
  invoke.add_argument('--contract-id', {
    default: DEFAULT_CONTRACT_ID,
    help: 'Contract ID to invoke.',
  });
  invoke.add_argument('--network', {
    default: 'local',
    help: 'Network profile or RPC alias (default: local).',
  });
  invoke.add_argument('--source-account', '--source', {
    dest: 'source',
    default: 'alice',
    help: 'Source account/identity for the transaction (default: alice).',
  });
  invoke.add_argument('--send', {
    default: 'default',
    choices: ['default', 'no', 'yes'],
    help: 'Forward to `stellar contract invoke --send` (default behavior matches CLI default).',
  });
  invoke.add_argument('--cost', {
    action: 'store_true',
    help: 'Include `--cost` when calling stellar CLI.',
  });
  invoke.add_argument('--proof-blob-file', {
    type: 'str',
    help: 'Write packed proof blob to this path and reuse it instead of a temporary file.',
    default: null,
  });
  invoke.add_argument('--dry-run', {
    action: 'store_true',
    help: 'Print the CLI commands instead of executing them.',
  });

  const setVk = subparsers.add_parser('set-vk', {
    help: 'Invoke set_vk to store the verification key.',
  });
  addArtifactArgs(setVk);
  setVk.add_argument('--contract-id', {
    default: DEFAULT_CONTRACT_ID,
    help: 'Contract ID to invoke.',
  });
  setVk.add_argument('--network', {
    default: 'local',
    help: 'Network profile or RPC alias (default: local).',
  });
  setVk.add_argument('--source-account', '--source', {
    dest: 'source',
    default: 'alice',
    help: 'Source account/identity for the transaction (default: alice).',
  });
  setVk.add_argument('--send', {
    default: 'default',
    choices: ['default', 'no', 'yes'],
    help: 'Forward to `stellar contract invoke --send` (default behavior matches CLI default).',
  });
  setVk.add_argument('--cost', {
    action: 'store_true',
    help: 'Include `--cost` when calling stellar CLI.',
  });
  setVk.add_argument('--dry-run', {
    action: 'store_true',
    help: 'Print the CLI commands instead of executing them.',
  });

  return parser;
}

async function main(argv?: string[]): Promise<number> {
  const parser = buildParser();
  const args = parser.parse_args(argv);

  switch (args.command) {
    case 'prepare':
      return commandPrepare(args);
    case 'invoke':
      return commandInvoke(args);
    case 'set-vk':
      return commandSetVk(args);
    default:
      console.error(`Unknown command: ${args.command}`);
      return 1;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });

#!/usr/bin/env ts-node
/**
 * Helper utilities for invoking the UltraHonk verifier contract.
 *
 * The contract expects three byte arguments:
 *   1. vk_bytes        → preprocessed verification key bytes
 *   2. public_inputs   → concatenated public inputs (32-byte each)
 *   3. proof_bytes     → raw proof bytes
 *
 * This script can:
 *   * prepare/print artifacts for inspection
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

function printSummary(artifacts: PackedArtifacts): void {
  console.log('vk_json:', artifacts.vkJsonPath);
  console.log('public inputs bytes:', artifacts.publicInputsBytes.length);
  console.log('proof bytes:', artifacts.proofBytes.length);
  console.log('proof fields:', getProofFields(artifacts));
  console.log('public input fields:', getPublicInputFields(artifacts));
  console.log('total fields:', getProofFields(artifacts) + getPublicInputFields(artifacts));
}

async function commandPrepare(args: any): Promise<number> {
  try {
    const artifacts = loadArtifacts(
      args.dataset,
      args.vk_json,
      args.public_inputs,
      args.proof
    );
    printSummary(artifacts);

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
    printSummary(artifacts);

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
      const publicInputsFile = path.join(tmpDir, 'public_inputs.bin');
      fs.writeFileSync(publicInputsFile, artifacts.publicInputsBytes);
      const proofFile = path.join(tmpDir, 'proof.bin');
      fs.writeFileSync(proofFile, artifacts.proofBytes);

      const verifyArgs = [
        '--vk_bytes-file-path',
        vkFile,
        '--public_inputs-file-path',
        publicInputsFile,
        '--proof_bytes-file-path',
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
    help: 'Load artifacts and print a summary.',
  });
  addArtifactArgs(prepare);

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

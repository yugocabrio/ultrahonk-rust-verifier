#!/usr/bin/env ts-node
/**
 * Helper utilities for invoking the UltraHonk verifier contract.
 *
 * The contract expects two byte arguments:
 *   1. public_inputs   → concatenated public inputs (32-byte each)
 *   2. proof_bytes     → raw proof bytes
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
import { spawn } from 'child_process';
import { ArgumentParser } from 'argparse';

// === Constants ===============================================================

const DEFAULT_CONTRACT_ID = 'CD6HGS5V7XJPSPJ5HHPHUZXLYGZAJJC3L6QWR4YZG4NIRO65UYQ6KIYP';
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const DEFAULT_DATASET_DIR = path.resolve(REPO_ROOT, 'tests', 'simple_circuit', 'target');

// === Data loading / packing ==================================================

interface PackedArtifacts {
  publicInputsBytes: Buffer;
  proofBytes: Buffer;
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
  publicInputs: string | null,
  proof: string | null
): PackedArtifacts {
  let datasetDir = dataset ?? DEFAULT_DATASET_DIR;
  if (!path.isAbsolute(datasetDir)) {
    datasetDir = path.resolve(process.cwd(), datasetDir);
  }

  const publicInputsPath = publicInputs ?? path.join(datasetDir, 'public_inputs');
  const proofPath = proof ?? path.join(datasetDir, 'proof');

  const resolvedPublicInputs = path.resolve(publicInputsPath);
  const resolvedProof = path.resolve(proofPath);

  if (!fs.existsSync(resolvedPublicInputs)) {
    throw new Error(`public inputs not found: ${resolvedPublicInputs}`);
  }
  if (!fs.existsSync(resolvedProof)) {
    throw new Error(`proof not found: ${resolvedProof}`);
  }

  return {
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
  console.log('public inputs bytes:', artifacts.publicInputsBytes.length);
  console.log('proof bytes:', artifacts.proofBytes.length);
  console.log('proof fields:', getProofFields(artifacts));
  console.log('public input fields:', getPublicInputFields(artifacts));
  console.log('total fields:', getProofFields(artifacts) + getPublicInputFields(artifacts));
}

async function commandPrepare(args: any): Promise<number> {
  try {
    const artifacts = loadArtifacts(args.dataset, args.public_inputs, args.proof);
    printSummary(artifacts);

    return 0;
  } catch (exc: any) {
    console.error(`error: ${exc.message}`);
    return 1;
  }
}

async function commandInvoke(args: any): Promise<number> {
  try {
    const artifacts = loadArtifacts(args.dataset, args.public_inputs, args.proof);
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
      const publicInputsFile = path.join(tmpDir, 'public_inputs.bin');
      fs.writeFileSync(publicInputsFile, artifacts.publicInputsBytes);
      const proofFile = path.join(tmpDir, 'proof.bin');
      fs.writeFileSync(proofFile, artifacts.proofBytes);

      const verifyArgs = [
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
      help: `Directory containing public_inputs and proof. Defaults to ${DEFAULT_DATASET_DIR}`,
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

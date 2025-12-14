#!/usr/bin/env ts-node
/**
 * Measure resource costs (CPU / memory / min resource fee) for UltraHonk
 * contract methods living on an actual Soroban network.
 *
 * Typical usage (local Quickstart):
 *   cd scripts/measure_ultrahonk_costs
 *   npm install
 *   npm run measure -- \
 *     --contract-id <CONTRACT_ID> \
 *     --source-secret <SECRET> \
 *     --rpc-url http://localhost:8000/soroban/rpc \
 *     --dataset ../../tests/simple_circuit/target
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { ArgumentParser } from 'argparse';
import {
  Contract,
  Keypair,
  Networks,
  SorobanRpc,
  TimeoutInfinite,
  TransactionBuilder,
  nativeToScVal,
  xdr,
} from '@stellar/stellar-sdk';

const PROJECT_ROOT = path.resolve(__dirname, '..', '..');
const PREPROCESS_MANIFEST = path.join(PROJECT_ROOT, 'preprocess_vk_cli', 'Cargo.toml');
const DEFAULT_DATASET_DIR = path.join(PROJECT_ROOT, 'tests', 'simple_circuit', 'target');
const DEFAULT_RPC_URL = 'http://localhost:8000/soroban/rpc';
const DEFAULT_NETWORK_PASSPHRASE = Networks.STANDALONE;
const FIELD_BYTES = 32;
const PROOF_NUM_FIELDS = 456;

interface Artifacts {
  vkBytes: Buffer;
  proofBlob: Buffer;
}

interface MeasureResult {
  cpu: bigint;
  mem: bigint;
  minFee: bigint;
}

function runPreprocessVk(vkJsonPath: string): Buffer {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'preprocess-vk-'));
  const outPath = path.join(tmpDir, 'vk.bin');
  try {
    const result = spawnSync(
      'cargo',
      ['run', '--quiet', '--manifest-path', PREPROCESS_MANIFEST, '--', vkJsonPath, outPath],
      {
        cwd: PROJECT_ROOT,
        stdio: 'inherit',
      }
    );
    if (result.status !== 0) {
      throw new Error('preprocess_vk CLI failed');
    }
    return fs.readFileSync(outPath);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function buildProofBlob(publicInputs: Buffer, proof: Buffer): Buffer {
  if (publicInputs.length % FIELD_BYTES !== 0) {
    throw new Error('public_inputs length is not a multiple of 32 bytes');
  }
  if (proof.length % FIELD_BYTES !== 0) {
    throw new Error('proof length is not a multiple of 32 bytes');
  }
  const publicInputFields = publicInputs.length / FIELD_BYTES;
  const totalFields = PROOF_NUM_FIELDS + publicInputFields;
  const header = Buffer.alloc(4);
  header.writeUInt32BE(totalFields, 0);
  return Buffer.concat([header, publicInputs, proof]);
}

function loadArtifacts(datasetDir: string): Artifacts {
  const vkJsonPath = path.resolve(datasetDir, 'vk_fields.json');
  const proofPath = path.resolve(datasetDir, 'proof');
  const publicInputsPath = path.resolve(datasetDir, 'public_inputs');
  for (const file of [vkJsonPath, proofPath, publicInputsPath]) {
    if (!fs.existsSync(file)) {
      throw new Error(`Missing artifact: ${file}`);
    }
  }
  const vkBytes = runPreprocessVk(vkJsonPath);
  const proofBytes = fs.readFileSync(proofPath);
  const publicInputsBytes = fs.readFileSync(publicInputsPath);
  const proofBlob = buildProofBlob(publicInputsBytes, proofBytes);
  return { vkBytes, proofBlob };
}

function bigIntFromXdr(value?: xdr.Int64 | xdr.Uint64 | number | string | null): bigint {
  if (value === undefined || value === null) {
    return 0n;
  }
  if (typeof value === 'number') {
    return BigInt(value);
  }
  if (typeof value === 'string') {
    return BigInt(value);
  }
  return BigInt(value.toString());
}

async function measureMethod(
  server: SorobanRpc.Server,
  keypair: Keypair,
  networkPassphrase: string,
  contractId: string,
  method: string,
  args: xdr.ScVal[]
): Promise<MeasureResult> {
  const account = await server.getAccount(keypair.publicKey());
  const contract = new Contract(contractId);
  const tx = new TransactionBuilder(account, {
    fee: '100',
    networkPassphrase,
  })
    .addOperation(contract.call(method, ...args))
    .setTimeout(TimeoutInfinite)
    .build();

  const sim = await server.simulateTransaction(tx);
  if (!SorobanRpc.Api.isSimulationSuccess(sim)) {
    throw new Error(`Simulation for ${method} failed: ${JSON.stringify(sim)}`);
  }

  const resources = sim.transactionData.build().resources();
  const cpu = bigIntFromXdr(resources.instructions());
  const mem =
    bigIntFromXdr(resources.readBytes()) + bigIntFromXdr(resources.writeBytes());
  const minFee = bigIntFromXdr(sim.minResourceFee);

  return { cpu, mem, minFee };
}

function printResult(name: string, result: MeasureResult) {
  const cpu = result.cpu.toString();
  const mem = result.mem.toString();
  const fee = result.minFee.toString();
  console.log(`\n=== ${name} ===`);
  console.log(`CPU instructions : ${cpu}`);
  console.log(`Memory bytes     : ${mem}`);
  console.log(`Min resource fee : ${fee} stroops`);
}

async function main() {
  const parser = new ArgumentParser({
    description: 'Measure UltraHonk verifier contract costs',
  });
  parser.add_argument('--contract-id', { required: true, help: 'Contract ID' });
  parser.add_argument('--source-secret', {
    required: true,
    help: 'Secret key for the funding account',
  });
  parser.add_argument('--dataset', {
    default: DEFAULT_DATASET_DIR,
    help: 'Directory with vk_fields.json, public_inputs, proof',
  });
  parser.add_argument('--rpc-url', {
    default: DEFAULT_RPC_URL,
    help: 'Soroban RPC URL',
  });
  parser.add_argument('--network-passphrase', {
    default: DEFAULT_NETWORK_PASSPHRASE,
    help: 'Network passphrase',
  });

  const args = parser.parse_args();
  const artifacts = loadArtifacts(args.dataset);
  const server = new SorobanRpc.Server(args.rpc_url, { allowHttp: true });
  const keypair = Keypair.fromSecret(args.source_secret);
  const vkScVal = nativeToScVal(artifacts.vkBytes, { type: 'bytes' });
  const proofBlobScVal = nativeToScVal(artifacts.proofBlob, { type: 'bytes' });

  console.log(`Dataset       : ${args.dataset}`);
  console.log(`Contract ID   : ${args.contract_id}`);
  console.log(`Source account: ${keypair.publicKey()}`);

  const setVkResult = await measureMethod(
    server,
    keypair,
    args.network_passphrase,
    args.contract_id,
    'set_vk',
    [vkScVal]
  );
  printResult('set_vk', setVkResult);

  const verifyResult = await measureMethod(
    server,
    keypair,
    args.network_passphrase,
    args.contract_id,
    'verify_proof',
    [vkScVal, proofBlobScVal]
  );
  printResult('verify_proof', verifyResult);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

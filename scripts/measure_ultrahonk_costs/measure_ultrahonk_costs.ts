#!/usr/bin/env ts-node
/**
 * Measure CPU/memory costs for UltraHonk verifier contract methods.
 *
 * Usage:
 *   ts-node scripts/measure_ultrahonk_costs.ts \
 *     --contract-id <CONTRACT_ID> \
 *     --network local \
 *     --source-account alice
 *
 * Prerequisites:
 *   npm install @stellar/stellar-sdk argparse
 */

import {
  Keypair,
  Contract,
  TransactionBuilder,
  SorobanRpc,
  xdr,
  Networks,
  TimeoutInfinite,
  Address,
  nativeToScVal,
  scValToNative,
} from '@stellar/stellar-sdk';
import * as fs from 'fs';
import * as path from 'path';
import { ArgumentParser } from 'argparse';

// --- Constants & Defaults ---

const DEFAULT_CONTRACT_ID = 'CAL4FBW62GLCOZ3RUHPQQGWC5ANDAMCH5SPPFIZUA24Q3LY2U2GNP4NT';
const DEFAULT_NETWORK_PASSPHRASE = Networks.STANDALONE;
const DEFAULT_RPC_URL = 'http://localhost:8000/soroban/rpc';

// Alice's secret key for local standalone network
const ALICE_SECRET = 'SDBXWELRSGKFPM3J367XJFMG3CU5NQJYFJMYCMIBTTMCAYKEX5EVSWKA';

// --- Helper Functions ---

function loadArtifacts(datasetDir: string) {
  const vkPath = path.join(datasetDir, 'vk_fields.json');
  const proofPath = path.join(datasetDir, 'proof');
  const pubInputsPath = path.join(datasetDir, 'public_inputs');

  if (!fs.existsSync(vkPath) || !fs.existsSync(proofPath) || !fs.existsSync(pubInputsPath)) {
    throw new Error(`Artifacts not found in ${datasetDir}. Ensure vk_fields.json, proof, and public_inputs exist.`);
  }

  const vkJson = fs.readFileSync(vkPath);
  const proof = fs.readFileSync(proofPath);
  const publicInputs = fs.readFileSync(pubInputsPath);

  return { vkJson, proof, publicInputs };
}

function buildProofBlob(proof: Buffer, publicInputs: Buffer): Buffer {
  // Format: [4-byte count of fields (BE)] || [public_inputs] || [proof]
  // public_inputs is expected to be a sequence of 32-byte fields.
  
  const fieldSize = 32;
  if (publicInputs.length % fieldSize !== 0) {
    throw new Error(`Public inputs length ${publicInputs.length} is not a multiple of 32.`);
  }
  
  const totalFields = publicInputs.length / fieldSize;
  const countBuffer = Buffer.alloc(4);
  countBuffer.writeUInt32BE(totalFields, 0);
  
  return Buffer.concat([countBuffer, publicInputs, proof]);
}

// Simple Keccak-256 implementation (using js-sha3 if available, or a placeholder if not)
// Since we want to avoid too many deps, we'll try to use the simulation result to get the hash
// or just use a dummy hash for is_verified if we haven't run verify_proof.
// However, for accurate cost measurement of is_verified, we should pass a valid-looking hash.
// We'll use a random 32-byte buffer if we can't compute it easily without deps.
function getDummyProofId(): Buffer {
    return Buffer.alloc(32, 0xab);
}

async function measureCost(
  server: SorobanRpc.Server,
  keypair: Keypair,
  contractId: string,
  method: string,
  args: xdr.ScVal[]
) {
  const account = await server.getAccount(keypair.publicKey());
  
  const contract = new Contract(contractId);
  const tx = new TransactionBuilder(account, {
    fee: '100',
    networkPassphrase: DEFAULT_NETWORK_PASSPHRASE, // Adjust if using Futurenet/Testnet
  })
    .addOperation(contract.call(method, ...args))
    .setTimeout(TimeoutInfinite)
    .build();

  const sim = await server.simulateTransaction(tx);

  if (!SorobanRpc.Api.isSimulationSuccess(sim)) {
    console.error(`Simulation failed for ${method}:`, sim);
    return { cpu: null, mem: null, minFee: null };
  }

  const resources = sim.transactionData.build().resources();
  const cpu = resources.instructions();
  const readBytes = resources.readBytes();
  const writeBytes = resources.writeBytes();
  const mem = readBytes + writeBytes;
  const minFee = sim.minResourceFee;

  return { cpu, mem, minFee };
}

// --- Main Script ---

async function main() {
  const parser = new ArgumentParser({
    description: 'Measure CPU/memory costs for UltraHonk verifier contract methods.',
  });

  parser.add_argument('--contract-id', { default: DEFAULT_CONTRACT_ID, help: 'Contract ID' });
  parser.add_argument('--network', { default: 'local', help: 'Network (local, testnet, futurenet)' });
  parser.add_argument('--source-secret', { default: ALICE_SECRET, help: 'Source account secret key' });
  parser.add_argument('--dataset', { 
    default: path.resolve(__dirname, '../../tests/fib_chain/target'), 
    help: 'Path to dataset directory' 
  });
  parser.add_argument('--rpc-url', { default: DEFAULT_RPC_URL, help: 'RPC URL' });

  const args = parser.parse_args();

  // Setup
  const server = new SorobanRpc.Server(args.rpc_url, { allowHttp: true });
  const keypair = Keypair.fromSecret(args.source_secret);
  
  console.log(`Contract ID: ${args.contract_id}`);
  console.log(`Dataset: ${args.dataset}`);
  console.log(`Source: ${keypair.publicKey()}`);

  // Load Data
  const { vkJson, proof, publicInputs } = loadArtifacts(args.dataset);
  const proofBlob = buildProofBlob(proof, publicInputs);
  
  console.log(`VK JSON size: ${vkJson.length} bytes`);
  console.log(`Proof Blob size: ${proofBlob.length} bytes`);

  // Prepare Arguments
  const vkJsonScVal = nativeToScVal(vkJson, { type: 'bytes' });
  const proofBlobScVal = nativeToScVal(proofBlob, { type: 'bytes' });
  // For is_verified, we need a 32-byte hash. 
  // In a real scenario, this is the Keccak256 hash of the proof blob.
  // We'll use a placeholder or the result from verify_proof if we could run it for real.
  const proofIdScVal = nativeToScVal(getDummyProofId(), { type: 'bytes' }); 

  // Define functions to measure
  const functions = [
    {
      name: 'set_vk',
      args: [vkJsonScVal],
    },
    {
      name: 'verify_proof',
      args: [vkJsonScVal, proofBlobScVal],
    },
    {
      name: 'verify_proof_with_stored_vk',
      args: [proofBlobScVal],
    },
    {
      name: 'is_verified',
      args: [proofIdScVal],
    },
  ];

  console.log('\nMeasuring costs...');
  console.log('----------------------------------------------------------------');

  for (const fn of functions) {
    try {
      const { cpu, mem, minFee } = await measureCost(
        server,
        keypair,
        args.contract_id,
        fn.name,
        fn.args
      );
      
      console.log(`Function: ${fn.name}`);
      if (cpu !== null && mem !== null && minFee !== null) {
        console.log(`CPU Instructions: ${parseInt(cpu.toString()).toLocaleString()}`);
        console.log(`Memory Bytes: ${parseInt(mem.toString()).toLocaleString()}`);
        const fee = parseInt(minFee);
        const feeXlm = fee / 10000000;
        console.log(`Fee: ${fee.toLocaleString()} stroops (${feeXlm} XLM)`);
      } else {
        console.log('Simulation failed or returned no resources.');
      }
      console.log('----------------------------------------------------------------');
    } catch (err: any) {
      console.error(`Error measuring ${fn.name}:`, err.message || err);
      console.log('----------------------------------------------------------------');
    }
  }
}

main().catch((err: any) => {
  console.error(err);
  process.exit(1);
});

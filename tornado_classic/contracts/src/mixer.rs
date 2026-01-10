extern crate alloc;

use alloc::{vec, vec::Vec};
use soroban_sdk::{
    contract, contracterror, contractimpl, symbol_short, Address, Bytes, BytesN, Env, InvokeError,
    IntoVal, Symbol, U256, Vec as SorobanVec, Val,
};
use ultrahonk_rust_verifier::PROOF_BYTES;

#[contract]
pub struct MixerContract;

#[contracterror]
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MixerError {
    CommitmentExists = 1,
    NullifierUsed = 2,
    VerificationFailed = 3,
    RootMismatch = 4,
    AdminNotConfigured = 5,
    AdminAlreadyConfigured = 6,
    NullifierMismatch = 7,
    TreeFull = 8,
    RootNotSet = 9,
    RootOverrideDisabled = 10,
}

fn key_count() -> Symbol { symbol_short!("cnt") }
fn key_commitment_prefix() -> Symbol { symbol_short!("cm") }
fn key_nullifier_prefix() -> Symbol { symbol_short!("nf") }
fn key_root() -> Symbol { symbol_short!("root") }
fn key_frontier_prefix() -> Symbol { symbol_short!("fr") }
fn key_next_index() -> Symbol { symbol_short!("idx") }
fn key_ci_prefix() -> Symbol { symbol_short!("ci") }
fn key_admin() -> Symbol { symbol_short!("adm") }

const TREE_DEPTH: u32 = 20;
const MAX_LEAVES: u32 = 1u32 << TREE_DEPTH;

fn poseidon2_hash2(env: &Env, a: &BytesN<32>, b: &BytesN<32>) -> BytesN<32> {
    let mut inputs = SorobanVec::new(env);
    inputs.push_back(U256::from_be_bytes(env, a.as_ref()));
    inputs.push_back(U256::from_be_bytes(env, b.as_ref()));
    let out = env.crypto().poseidon2_hash(&inputs, symbol_short!("BN254"));
    let out_bytes = out.to_be_bytes();
    let mut out_arr = [0u8; 32];
    out_bytes.copy_into_slice(&mut out_arr);
    BytesN::from_array(env, &out_arr)
}

fn zero_at(env: &Env, level: u32) -> BytesN<32> {
    // zero[0] = 0; zero[i+1] = H(zero[i], zero[i])
    let mut z = BytesN::from_array(env, &[0u8; 32]);
    if level == 0 { return z; }
    for _ in 0..level {
        let zz = z.clone();
        z = poseidon2_hash2(env, &zz, &zz);
    }
    z
}

fn parse_public_inputs(bytes: &[u8]) -> Result<Vec<[u8; 32]>, MixerError> {
    if bytes.len() % 32 != 0 {
        return Err(MixerError::VerificationFailed);
    }
    let mut out = Vec::with_capacity(bytes.len() / 32);
    for chunk in bytes.chunks(32) {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(chunk);
        out.push(arr);
    }
    Ok(out)
}

#[contractimpl]
impl MixerContract {
    /// Inserts a new leaf into the Poseidon2 Merkle tree and returns its index.
    pub fn deposit(env: Env, commitment: BytesN<32>) -> Result<u32, MixerError> {
        let cm_key = (key_commitment_prefix(), commitment.clone());
        if env.storage().instance().has(&cm_key) {
            return Err(MixerError::CommitmentExists);
        }
        let count_key = key_count();
        let mut count: u32 = env.storage().instance().get(&count_key).unwrap_or(0u32);
        let idx = count;
        count = count.saturating_add(1);
        env.storage().instance().set(&count_key, &count);
        env.storage().instance().set(&cm_key, &true);
        // save idx => commitment mapping and emit event
        let ci_key = (key_ci_prefix(), idx);
        env.storage().instance().set(&ci_key, &commitment);
        env.events().publish((symbol_short!("deposit"), idx), commitment.clone());

        // Incremental Merkle: frontier + next_index
        let mut next_index: u32 = env
            .storage()
            .instance()
            .get(&key_next_index())
            .unwrap_or(0u32);
        if next_index >= MAX_LEAVES {
            return Err(MixerError::TreeFull);
        }
        // leaf index used for insertion
        let ins_idx = next_index;
        let mut cur = commitment.clone();
        let mut i = 0u32;
        while i < TREE_DEPTH {
            let bit = (ins_idx >> i) & 1;
            if bit == 0 {
                // save left sibling at this level, pair with zero
                let fk = (key_frontier_prefix(), i);
                env.storage().instance().set(&fk, &cur);
                let z = zero_at(&env, i);
                cur = poseidon2_hash2(&env, &cur, &z);
            } else {
                // combine with existing left sibling
                let fk = (key_frontier_prefix(), i);
                let left: BytesN<32> = env
                    .storage()
                    .instance()
                    .get(&fk)
                    .unwrap_or_else(|| zero_at(&env, i));
                cur = poseidon2_hash2(&env, &left, &cur);
            }
            i += 1;
        }
        // update root and next_index
        env.storage().instance().set(&key_root(), &cur);
        next_index = next_index.saturating_add(1);
        env.storage().instance().set(&key_next_index(), &next_index);

        Ok(idx)
    }

    /// Verifies a proof with the stored verification key and marks the nullifier spent.
    /// The public inputs are ordered as `[root, nullifier_hash, recipient]`.
    pub fn withdraw(
        env: Env,
        verifier: Address,
        public_inputs: Bytes,
        proof_bytes: Bytes,
        nullifier_hash: BytesN<32>,
    ) -> Result<(), MixerError> {
        if proof_bytes.len() as usize != PROOF_BYTES {
            return Err(MixerError::VerificationFailed);
        }
        let mut pis_buf = vec![0u8; public_inputs.len() as usize];
        public_inputs.copy_into_slice(&mut pis_buf);
        let pub_inputs = parse_public_inputs(&pis_buf)?;
        if pub_inputs.len() < 3 {
            return Err(MixerError::VerificationFailed);
        }
        // Interpret public inputs as `[root, nullifier_hash, recipient]`.
        let mut root_arr = [0u8; 32];
        root_arr.copy_from_slice(&pub_inputs[0]);
        let mut nf_arr = [0u8; 32];
        nf_arr.copy_from_slice(&pub_inputs[1]);
        let nf_from_proof = BytesN::from_array(&env, &nf_arr);
        // Caller must pass the same nullifier hash as the proof to prevent hijacking another leaf’s proof.
        if nf_from_proof != nullifier_hash {
            return Err(MixerError::NullifierMismatch);
        }
        // Nullifier indicates a spent note; fail if already seen.
        let nf_key = (key_nullifier_prefix(), nf_from_proof.clone());
        if env.storage().instance().has(&nf_key) {
            return Err(MixerError::NullifierUsed);
        }
        let mut rcpt_arr = [0u8; 32];
        rcpt_arr.copy_from_slice(&pub_inputs[2]);
        let root_from_proof = BytesN::from_array(&env, &root_arr);
        // Proof must bind to the current Merkle root.
        let stored_root: BytesN<32> = env
            .storage()
            .instance()
            .get(&key_root())
            .ok_or(MixerError::RootNotSet)?;
        if stored_root != root_from_proof {
            return Err(MixerError::RootMismatch);
        }
        // Verify proof against the stored VK on the external verifier contract.
        let mut args: SorobanVec<Val> = SorobanVec::new(&env);
        args.push_back(public_inputs.into_val(&env));
        args.push_back(proof_bytes.into_val(&env));
        env.try_invoke_contract::<(), InvokeError>(&verifier, &Symbol::new(&env, "verify_proof"), args)
            .map_err(|_| MixerError::VerificationFailed)?
            .map_err(|_| MixerError::VerificationFailed)?;
        // Mark nullifier as spent and emit withdraw event containing recipient.
        env.storage().instance().set(&nf_key, &true);
        let rcpt = BytesN::from_array(&env, &rcpt_arr);
        env.events()
            .publish((symbol_short!("withdraw"), nf_from_proof.clone()), rcpt);
        Ok(())
    }

    /// Returns true if the commitment has been seen in the tree.
    pub fn has_commitment(env: Env, commitment: BytesN<32>) -> bool {
        let cm_key = (key_commitment_prefix(), commitment);
        env.storage().instance().has(&cm_key)
    }

    /// Returns true if the nullifier hash has already been consumed.
    pub fn is_nullifier_used(env: Env, nullifier_hash: BytesN<32>) -> bool {
        let nf_key = (key_nullifier_prefix(), nullifier_hash);
        env.storage().instance().has(&nf_key)
    }

    /// Sets the admin and seeds the tree with the empty Poseidon root; only callable once.
    pub fn configure(env: Env, admin: Address) -> Result<(), MixerError> {
        let key = key_admin();
        if env.storage().instance().has(&key) {
            return Err(MixerError::AdminAlreadyConfigured);
        }
        admin.require_auth();
        env.storage().instance().set(&key, &admin);
        let empty_root = zero_at(&env, TREE_DEPTH);
        env.storage().instance().set(&key_root(), &empty_root);
        env.storage().instance().set(&key_next_index(), &0u32);
        env.storage().instance().set(&key_count(), &0u32);
        Ok(())
    }

    /// Test-only helper to override the stored root when running under debug builds.
    pub fn set_root(env: Env, root: BytesN<32>) -> Result<(), MixerError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&key_admin())
            .ok_or(MixerError::AdminNotConfigured)?;
        admin.require_auth();
        if !cfg!(debug_assertions) && !cfg!(feature = "wasm-cost") {
            return Err(MixerError::RootOverrideDisabled);
        }
        env.storage().instance().set(&key_root(), &root);
        Ok(())
    }

    /// Returns the current Poseidon tree root.
    pub fn get_root(env: Env) -> Option<BytesN<32>> {
        env.storage().instance().get(&key_root())
    }

    /// Retrieves the commitment stored at a given leaf index.
    pub fn get_commitment_by_index(env: Env, index: u32) -> Option<BytesN<32>> {
        let ci_key = (key_ci_prefix(), index);
        env.storage().instance().get(&ci_key)
    }
}

use soroban_sdk::{
    contract, contracterror, contractimpl, symbol_short, Address, Bytes, BytesN, Env, Symbol,
    IntoVal, Vec as SorobanVec, Val,
};

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

const TREE_DEPTH: u32 = 20; // match circuit depth for now
const MAX_LEAVES: u32 = 1u32 << TREE_DEPTH;

fn bytesn_to_arr(b: &BytesN<32>) -> [u8; 32] {
    let mut a = [0u8; 32];
    b.copy_into_slice(&mut a);
    a
}

fn arr_to_bytesn(env: &Env, a: [u8; 32]) -> BytesN<32> { BytesN::from_array(env, &a) }

fn poseidon2_hash2(env: &Env, a: &BytesN<32>, b: &BytesN<32>) -> BytesN<32> {
    let aa = bytesn_to_arr(a);
    let bb = bytesn_to_arr(b);
    let out = crate::hash2::permute_2_bytes_be(&aa, &bb);
    arr_to_bytesn(env, out)
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

fn split_inputs_and_proof_bytes(packed: &[u8]) -> (Vec<Vec<u8>>, Vec<u8>) {
    if packed.len() < 4 {
        return (Vec::new(), packed.to_vec());
    }
    let rest = &packed[4..];
    for &pf in &[456usize, 440usize] {
        let need = pf * 32;
        if rest.len() >= need {
            let pis_len = rest.len() - need;
            if pis_len % 32 == 0 {
                let mut pub_inputs_bytes: Vec<Vec<u8>> = Vec::with_capacity(pis_len / 32);
                for chunk in rest[..pis_len].chunks(32) {
                    pub_inputs_bytes.push(chunk.to_vec());
                }
                let proof_bytes = rest[pis_len..].to_vec();
                return (pub_inputs_bytes, proof_bytes);
            }
        }
    }
    (Vec::new(), rest.to_vec())
}

#[contractimpl]
impl MixerContract {
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

    /// Withdraw using stored VK and new public inputs ordering:
    /// public_inputs = [root, nullifier_hash, recipient]
    pub fn withdraw_v3(
        env: Env,
        verifier: Address,
        proof_blob: Bytes,
        nullifier_hash: BytesN<32>,
    ) -> Result<BytesN<32>, MixerError> {
        let packed_vec: Vec<u8> = proof_blob.to_alloc_vec();
        let (pub_inputs, _proof_bytes) = split_inputs_and_proof_bytes(&packed_vec);
        if pub_inputs.len() < 3 {
            return Err(MixerError::VerificationFailed);
        }
        if pub_inputs[0].len() != 32 || pub_inputs[1].len() != 32 || pub_inputs[2].len() != 32 {
            return Err(MixerError::VerificationFailed);
        }
        // [root, nullifier_hash, recipient]
        let mut root_arr = [0u8; 32];
        root_arr.copy_from_slice(&pub_inputs[0]);
        let mut nf_arr = [0u8; 32];
        nf_arr.copy_from_slice(&pub_inputs[1]);
        let nf_from_proof = BytesN::from_array(&env, &nf_arr);
        if nf_from_proof != nullifier_hash {
            return Err(MixerError::NullifierMismatch);
        }
        let nf_key = (key_nullifier_prefix(), nf_from_proof.clone());
        if env.storage().instance().has(&nf_key) {
            return Err(MixerError::NullifierUsed);
        }
        let mut rcpt_arr = [0u8; 32];
        rcpt_arr.copy_from_slice(&pub_inputs[2]);
        let root_from_proof = BytesN::from_array(&env, &root_arr);
        let stored_root: BytesN<32> = env
            .storage()
            .instance()
            .get(&key_root())
            .ok_or(MixerError::RootNotSet)?;
        if stored_root != root_from_proof {
            return Err(MixerError::RootMismatch);
        }
        // Verify via stored VK on verifier
        let mut args: SorobanVec<Val> = SorobanVec::new(&env);
        args.push_back(proof_blob.into_val(&env));
        let proof_id: BytesN<32> = env.invoke_contract(&verifier, &Symbol::new(&env, "verify_proof_with_stored_vk"), args);
        env.storage().instance().set(&nf_key, &true);
        let rcpt = BytesN::from_array(&env, &rcpt_arr);
        env.events()
            .publish((symbol_short!("withdraw"), nf_from_proof.clone()), rcpt);
        Ok(proof_id)
    }

    pub fn has_commitment(env: Env, commitment: BytesN<32>) -> bool {
        let cm_key = (key_commitment_prefix(), commitment);
        env.storage().instance().has(&cm_key)
    }

    pub fn is_nullifier_used(env: Env, nullifier_hash: BytesN<32>) -> bool {
        let nf_key = (key_nullifier_prefix(), nullifier_hash);
        env.storage().instance().has(&nf_key)
    }

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

    pub fn set_root(env: Env, root: BytesN<32>) -> Result<(), MixerError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&key_admin())
            .ok_or(MixerError::AdminNotConfigured)?;
        admin.require_auth();
        if !cfg!(debug_assertions) {
            return Err(MixerError::RootOverrideDisabled);
        }
        env.storage().instance().set(&key_root(), &root);
        Ok(())
    }

    pub fn get_root(env: Env) -> Option<BytesN<32>> {
        env.storage().instance().get(&key_root())
    }

    pub fn get_commitment_by_index(env: Env, index: u32) -> Option<BytesN<32>> {
        let ci_key = (key_ci_prefix(), index);
        env.storage().instance().get(&ci_key)
    }
}

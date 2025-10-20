use sha3::{Digest, Keccak256};

#[cfg(all(feature = "soroban-precompile", not(feature = "std")))]
use alloc::boxed::Box;
#[cfg(all(feature = "soroban-precompile", feature = "std"))]
use std::boxed::Box;

#[cfg(feature = "soroban-precompile")]
use once_cell::race::OnceBox;

/// Transcript hash backend abstraction trait.
pub trait HashOps: Send + Sync {
    fn hash(&self, data: &[u8]) -> [u8; 32];
}

pub struct KeccakBackend;

impl HashOps for KeccakBackend {
    #[inline(always)]
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

static KECCAK_BACKEND: KeccakBackend = KeccakBackend;

#[cfg(feature = "soroban-precompile")]
static BACKEND: OnceBox<Box<dyn HashOps>> = OnceBox::new();

#[inline(always)]
fn backend() -> &'static dyn HashOps {
    #[cfg(feature = "soroban-precompile")]
    {
        if let Some(b) = BACKEND.get() {
            return &**b;
        }
    }
    &KECCAK_BACKEND
}

/// Compute the active backend hash of the given data
#[inline(always)]
pub fn hash32(data: &[u8]) -> [u8; 32] {
    backend().hash(data)
}

#[cfg(feature = "soroban-precompile")]
/// Register a custom hash backend (Soroban precompile bridge).
pub fn set_backend(ops: Box<dyn HashOps>) {
    let _ = BACKEND.set(Box::new(ops));
}

#[cfg(feature = "soroban-precompile")]
#[inline(always)]
pub fn set_soroban_hash_backend(ops: Box<dyn HashOps>) {
    set_backend(ops)
}

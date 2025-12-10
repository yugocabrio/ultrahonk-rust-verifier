// In std builds we always keep a pure-Rust Keccak backend for tests and tools.
// For no_std + soroban-precompile (Soroban WASM) we rely solely on the host backend.
#[cfg(any(not(feature = "soroban-precompile"), feature = "std", test))]
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

#[cfg(any(not(feature = "soroban-precompile"), feature = "std", test))]
pub struct KeccakBackend;

#[cfg(any(not(feature = "soroban-precompile"), feature = "std", test))]
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

#[cfg(any(not(feature = "soroban-precompile"), feature = "std", test))]
static KECCAK_BACKEND: KeccakBackend = KeccakBackend;

#[cfg(all(feature = "soroban-precompile", not(feature = "std")))]
static BACKEND: OnceBox<Box<dyn HashOps>> = OnceBox::new();

#[inline(always)]
fn backend() -> &'static dyn HashOps {
    // Pure Soroban (no_std + soroban-precompile, non-test): rely on host backend.
    #[cfg(all(feature = "soroban-precompile", not(feature = "std"), not(test)))]
    {
        if let Some(b) = BACKEND.get() {
            return &**b;
        }
        unsafe { core::hint::unreachable_unchecked() }
    }

    // All other configurations (including tests) use the built-in Keccak backend.
    #[cfg(any(not(feature = "soroban-precompile"), feature = "std", test))]
    {
        &KECCAK_BACKEND
    }
}

/// Compute the active backend hash of the given data
#[inline(always)]
pub fn hash32(data: &[u8]) -> [u8; 32] {
    backend().hash(data)
}

#[cfg(all(feature = "soroban-precompile", not(feature = "std")))]
/// Register a custom hash backend (Soroban precompile bridge).
pub fn set_backend(ops: Box<dyn HashOps>) {
    let _ = BACKEND.set(Box::new(ops));
}

#[cfg(all(feature = "soroban-precompile", not(feature = "std")))]
#[inline(always)]
pub fn set_soroban_hash_backend(ops: Box<dyn HashOps>) {
    set_backend(ops)
}

#![cfg_attr(not(test), no_std)]

extern crate alloc;

// no features: always use the real verifier
#[path = "src/mixer.rs"]
pub mod mixer;

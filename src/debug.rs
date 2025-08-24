 

use crate::field::Fr;
use crate::types::G1Point;
use ark_ff::{BigInteger256, PrimeField};

#[cfg(not(feature = "std"))]
use alloc::{format, string::String};

/// trace! macro is a lightweight debug print macro that only outputs when the `trace` feature is enabled.
/// you can use it like this: cargo test --features trace -- --nocapture / cargo run --features trace
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        #[cfg(all(feature = "trace", feature = "std"))]
        {
            println!($($arg)*);
        }
    };
}

/// BigInteger256 → BE fixed-width hex (0x + 64 nibbles)
/// This is used to convert the internal representation of Fr to a hex string.
#[inline(always)]
fn bigint256_to_hex(b: &BigInteger256) -> String {
    let mut s = String::from("0x");
    for limb in b.0.iter().rev() {
        s.push_str(&format!("{:016x}", limb));
    }
    s
}

/// ark_bn254::Fr → BE fixed-width hex (0x + 64 nibbles)
#[inline(always)]
pub fn fr_to_hex(fr: &Fr) -> String {
    bigint256_to_hex(&fr.0.into_bigint())
}

/// G1Point → (x_hex, y_hex)
#[inline(always)]
pub fn g1_to_hex(pt: &G1Point) -> (String, String) {
    (
        bigint256_to_hex(&pt.x.into_bigint()),
        bigint256_to_hex(&pt.y.into_bigint()),
    )
}

/// Outputs commitment/scalar pairs
pub fn dump_pairs(coms: &[G1Point], scalars: &[Fr], head_tail: usize) {
    assert_eq!(
        coms.len(),
        scalars.len(),
        "commitment / scalar length mismatch"
    );

    let len = coms.len();
    trace!("========= FULL LIST =========");
    for i in 0..len {
        if head_tail != usize::MAX && i >= head_tail && i < len - head_tail {
            if i == head_tail {
                trace!("    ...");
            }
            continue;
        }
        let (x_hex, y_hex) = g1_to_hex(&coms[i]);
        let s_hex = fr_to_hex(&scalars[i]);
        trace!(
            "[#{:02}]  s = {:>66}  C.x = {:>66}  C.y = {:>66}",
            i,
            s_hex,
            x_hex,
            y_hex
        );
    }
    trace!("================================");
}

/// Outputs a specific slice of commitment/scalar pairs, useful for
/// cross-checking against Solidity's first 40 entities (1..=40).
#[allow(dead_code)]
pub fn dump_pairs_range(coms: &[G1Point], scalars: &[Fr], start: usize, end_inclusive: usize) {
    assert_eq!(coms.len(), scalars.len(), "commitment / scalar length mismatch");
    let end = end_inclusive.min(coms.len().saturating_sub(1));
    let start = start.min(end);
    trace!("========= RANGE LIST [{}..={}] =========", start, end);
    for i in start..=end {
        let (x_hex, y_hex) = g1_to_hex(&coms[i]);
        let s_hex = fr_to_hex(&scalars[i]);
        trace!(
            "[#{:02}]  s = {}  C.x = {}  C.y = {}",
            i, s_hex, x_hex, y_hex
        );
    }
    trace!("========================================");
}

/// Debug Fr vector with hex output
#[inline(always)]
pub fn dbg_vec(tag: &str, xs: &[Fr]) {
    for (i, v) in xs.iter().enumerate() {
        trace!(
            "{tag}[{i:02}] = 0x{}",
            hex::encode(v.to_bytes()),
            tag = tag,
            i = i
        );
    }
}

/// Debug Fr with hex output
#[inline(always)]
pub fn dbg_fr(tag: &str, x: &Fr) {
    trace!("{:<18}: 0x{}", tag, hex::encode(x.to_bytes()));
}

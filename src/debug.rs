use crate::field::Fr;
use crate::types::G1Point;

#[cfg(not(feature = "std"))]
use alloc::string::String;

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

/// ark_bn254::Fr → BE fixed-width hex (0x + 64 nibbles)
#[inline(always)]
pub fn fr_to_hex(fr: &Fr) -> String {
    let mut s = String::from("0x");
    s.push_str(&hex::encode(fr.to_bytes()));
    s
}

/// G1Point → (x_hex, y_hex)
#[inline(always)]
pub fn g1_to_hex(pt: &G1Point) -> (String, String) {
    let mut x = String::from("0x");
    let mut y = String::from("0x");
    x.push_str(&hex::encode(pt.x));
    y.push_str(&hex::encode(pt.y));
    (x, y)
}

/// Outputs commitment/scalar pairs
pub fn dump_pairs(coms: &[G1Point], scalars: &[Fr], head_tail: usize) {
    #[cfg(feature = "trace")]
    {
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
    #[cfg(not(feature = "trace"))]
    {
        let _ = (coms, scalars, head_tail);
    }
}

/// Outputs a specific slice of commitment/scalar pairs, useful for
/// cross-checking against Solidity's first 40 entities (1..=40).
#[allow(dead_code)]
pub fn dump_pairs_range(coms: &[G1Point], scalars: &[Fr], start: usize, end_inclusive: usize) {
    #[cfg(feature = "trace")]
    {
        assert_eq!(
            coms.len(),
            scalars.len(),
            "commitment / scalar length mismatch"
        );
        let end = end_inclusive.min(coms.len().saturating_sub(1));
        let start = start.min(end);
        trace!("========= RANGE LIST [{}..={}] =========", start, end);
        for i in start..=end {
            let (x_hex, y_hex) = g1_to_hex(&coms[i]);
            let s_hex = fr_to_hex(&scalars[i]);
            trace!(
                "[#{:02}]  s = {}  C.x = {}  C.y = {}",
                i,
                s_hex,
                x_hex,
                y_hex
            );
        }
        trace!("========================================");
    }
    #[cfg(not(feature = "trace"))]
    {
        let _ = (coms, scalars, start, end_inclusive);
    }
}

/// Debug Fr vector with hex output
#[inline(always)]
pub fn dbg_vec(tag: &str, xs: &[Fr]) {
    #[cfg(feature = "trace")]
    {
        for (i, v) in xs.iter().enumerate() {
            trace!(
                "{tag}[{i:02}] = 0x{}",
                hex::encode(v.to_bytes()),
                tag = tag,
                i = i
            );
        }
    }
    #[cfg(not(feature = "trace"))]
    {
        let _ = (tag, xs);
    }
}

/// Debug Fr with hex output
#[inline(always)]
pub fn dbg_fr(tag: &str, x: &Fr) {
    #[cfg(feature = "trace")]
    {
        trace!("{:<18}: 0x{}", tag, hex::encode(x.to_bytes()));
    }
    #[cfg(not(feature = "trace"))]
    {
        let _ = (tag, x);
    }
}

use num_bigint::BigUint;
use soroban_poseidon::{poseidon2_hash, Field};
use soroban_sdk::{crypto::BnScalar, Bytes, Env, U256, Vec as SorobanVec};
use std::{env, fs, path::Path};

const TREE_DEPTH: usize = 20;
const DEFAULT_SEED: u64 = 1;

struct Lcg {
    state: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1);
        self.state
    }
}

fn env_flag(name: &str) -> bool {
    matches!(
        env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

fn format_list(label: &str, values: &[String]) -> String {
    let mut out = String::new();
    out.push_str(label);
    out.push_str(" = [\n");
    for (i, v) in values.iter().enumerate() {
        out.push_str("  \"");
        out.push_str(v);
        out.push('"');
        let last = i + 1 == values.len();
        if last {
            out.push('\n');
        } else {
            out.push(',');
            if (i + 1) % 5 == 0 {
                out.push('\n');
            } else {
                out.push(' ');
            }
        }
    }
    out.push_str("]\n");
    out
}

fn be32_from_biguint(x: &BigUint) -> [u8; 32] {
    let mut be = x.to_bytes_be();
    if be.len() > 32 {
        be = be[be.len() - 32..].to_vec();
    }
    let mut out = [0u8; 32];
    let start = 32 - be.len();
    out[start..].copy_from_slice(&be);
    out
}

fn biguint_from_dec(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 10).expect("invalid decimal")
}

fn field_hash2(env: &Env, a: &BigUint, b: &BigUint) -> BigUint {
    let aa = be32_from_biguint(a);
    let bb = be32_from_biguint(b);
    let a_bytes = Bytes::from_array(env, &aa);
    let b_bytes = Bytes::from_array(env, &bb);
    let modulus = <BnScalar as Field>::modulus(env);
    let mut inputs = SorobanVec::new(env);
    inputs.push_back(U256::from_be_bytes(env, &a_bytes).rem_euclid(&modulus));
    inputs.push_back(U256::from_be_bytes(env, &b_bytes).rem_euclid(&modulus));
    let out = poseidon2_hash::<4, BnScalar>(env, &inputs);
    let out_bytes = out.to_be_bytes();
    let mut out_arr = [0u8; 32];
    out_bytes.copy_into_slice(&mut out_arr);
    BigUint::from_bytes_be(&out_arr)
}

fn compute_root(env: &Env, leaf: &BigUint, siblings: &[BigUint], bits: &[u8]) -> BigUint {
    let mut cur = leaf.clone();
    for (i, sib) in siblings.iter().enumerate() {
        let b = bits[i];
        if b == 0 {
            cur = field_hash2(env, &cur, sib);
        } else {
            cur = field_hash2(env, sib, &cur);
        }
    }
    cur
}

fn main() {
    let env = Env::default();
    let prover_path = Path::new("tornado_classic/circuit/Prover.toml");
    let content = fs::read_to_string(prover_path).unwrap_or_default();
    let generate = env_flag("TORNADO_GENERATE");
    let seed = env::var("TORNADO_SEED")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SEED);

    let mut nullifier = BigUint::from(0u32);
    let mut secret = BigUint::from(0u32);
    let mut siblings: Vec<BigUint> = Vec::new();
    let mut bits: Vec<u8> = Vec::new();
    let base_content: String;

    if generate {
        let mut rng = Lcg::new(seed);
        nullifier = BigUint::from(rng.next_u64());
        secret = BigUint::from(rng.next_u64());
        siblings = (0..TREE_DEPTH)
            .map(|_| BigUint::from(rng.next_u64()))
            .collect();
        bits = (0..TREE_DEPTH).map(|_| (rng.next_u64() & 1) as u8).collect();

        let sibling_strings: Vec<String> = siblings.iter().map(|v| v.to_string()).collect();
        let bit_strings: Vec<String> = bits.iter().map(|v| v.to_string()).collect();
        let mut base = String::new();
        base.push_str(&format!("nullifier = \"{}\"\n", nullifier));
        base.push_str(&format!("secret = \"{}\"\n", secret));
        base.push_str(&format_list("path_siblings", &sibling_strings));
        base.push_str(&format_list("path_bits", &bit_strings));
        base.push_str("\n# Public values are now outputs of the circuit (root, nullifier_hash).\n");
        base.push_str("# They no longer need to be provided here.\n");
        base_content = base;
    } else {
        let filtered: String = content
            .lines()
            .filter(|line| {
                let t = line.trim_start();
                !(t.starts_with("nullifier_hash = ")
                    || t.starts_with("root = ")
                    || t.starts_with("recipient = ")
                    || t.starts_with("path_index = "))
            })
            .map(|line| format!("{line}\n"))
            .collect();

        // naive parse tailored to current Prover.toml shape
        let mut i = 0usize;
        let lines: Vec<&str> = content.lines().collect();
        while i < lines.len() {
            let l = lines[i].trim();
            if l.starts_with("nullifier = ") {
                let v = l.split('=').nth(1).unwrap().trim().trim_matches('"');
                nullifier = biguint_from_dec(v);
            } else if l.starts_with("secret = ") {
                let v = l.split('=').nth(1).unwrap().trim().trim_matches('"');
                secret = biguint_from_dec(v);
            } else if l.starts_with("path_siblings = [") {
                let mut acc = String::new();
                acc.push_str(l);
                while !lines[i].contains(']') {
                    i += 1;
                    acc.push_str(lines[i].trim());
                }
                let inside = acc.split('[').nth(1).unwrap().split(']').next().unwrap();
                siblings = inside
                    .split(',')
                    .filter_map(|x| {
                        let t = x.trim().trim_matches('"');
                        if t.is_empty() { None } else { Some(biguint_from_dec(t)) }
                    })
                    .collect();
            } else if l.starts_with("path_bits = [") {
                let mut acc = String::new();
                acc.push_str(l);
                while !lines[i].contains(']') {
                    i += 1;
                    acc.push_str(lines[i].trim());
                }
                let inside = acc.split('[').nth(1).unwrap().split(']').next().unwrap();
                bits = inside
                    .split(',')
                    .filter_map(|x| {
                        let t = x.trim().trim_matches('"');
                        if t.is_empty() { None } else { Some(t.parse::<u8>().expect("bit")) }
                    })
                    .collect();
            }
            i += 1;
        }

        base_content = filtered;
    }

    assert_eq!(siblings.len(), bits.len(), "siblings/bits length mismatch");
    if generate {
        assert_eq!(siblings.len(), TREE_DEPTH, "path_siblings depth mismatch");
    }
    let leaf = field_hash2(&env, &nullifier, &secret);
    let nf = field_hash2(&env, &nullifier, &BigUint::from(0u32));
    let root = compute_root(&env, &leaf, &siblings, &bits);

    let mut path_index = BigUint::from(0u32);
    for (i, &b) in bits.iter().enumerate() {
        if b == 1 { path_index += BigUint::from(1u128) << i; }
    }
    // append updated fields at end (simple and explicit)
    let mut out = String::new();
    out.push_str(&base_content);
    out.push_str(&format!("nullifier_hash = \"{}\"\n", nf));
    out.push_str(&format!("root = \"{}\"\n", root));
    out.push_str(&format!("path_index = \"{}\"\n", path_index));
    fs::write(prover_path, out).expect("write Prover.toml");
    println!("Updated Prover.toml with public inputs and path_index");
}

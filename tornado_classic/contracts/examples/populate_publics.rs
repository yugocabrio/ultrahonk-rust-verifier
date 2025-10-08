use num_bigint::BigUint;
use std::{fs, path::Path};

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

fn field_hash2(a: &BigUint, b: &BigUint) -> BigUint {
    let aa = be32_from_biguint(a);
    let bb = be32_from_biguint(b);
    let out = tornado_classic_contracts::hash2::permute_2_bytes_be(&aa, &bb);
    BigUint::from_bytes_be(&out)
}

fn compute_root(leaf: &BigUint, siblings: &[BigUint], bits: &[u8]) -> BigUint {
    let mut cur = leaf.clone();
    for (i, sib) in siblings.iter().enumerate() {
        let b = bits[i];
        if b == 0 {
            cur = field_hash2(&cur, sib);
        } else {
            cur = field_hash2(sib, &cur);
        }
    }
    cur
}

fn main() {
    let prover_path = Path::new("tornado_classic/circuit/Prover.toml");
    let content = fs::read_to_string(prover_path).expect("read Prover.toml");

    // parse minimal fields we need
    let mut nullifier = BigUint::from(0u32);
    let mut secret = BigUint::from(0u32);
    let mut siblings: Vec<BigUint> = Vec::new();
    let mut bits: Vec<u8> = Vec::new();
    let mut recipient_opt: Option<BigUint> = None;

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
        } else if l.starts_with("recipient = ") {
            let v = l.split('=').nth(1).unwrap().trim().trim_matches('"');
            recipient_opt = Some(biguint_from_dec(v));
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

    assert_eq!(siblings.len(), bits.len(), "siblings/bits length mismatch");
    let leaf = field_hash2(&nullifier, &secret);
    let nf = field_hash2(&nullifier, &BigUint::from(0u32));
    let root = compute_root(&leaf, &siblings, &bits);

    let mut path_index = BigUint::from(0u32);
    for (i, &b) in bits.iter().enumerate() {
        if b == 1 { path_index += BigUint::from(1u128) << i; }
    }
    let recipient = recipient_opt.unwrap_or_else(|| BigUint::from(0u32));

    // append updated fields at end (simple and explicit)
    let mut out = String::new();
    out.push_str(&content);
    out.push_str(&format!("nullifier_hash = \"{}\"\n", nf));
    out.push_str(&format!("root = \"{}\"\n", root));
    out.push_str(&format!("recipient = \"{}\"\n", recipient));
    out.push_str(&format!("path_index = \"{}\"\n", path_index));
    fs::write(prover_path, out).expect("write Prover.toml");
    println!("Updated Prover.toml with public inputs and path_index");
}

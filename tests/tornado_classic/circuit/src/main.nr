// Tornado Classic-style circuit (Poseidon2-based)
// - Private inputs: nullifier, secret, Merkle path (siblings, path_bits)
// - Public outputs: root, nullifier_hash, commitment
// - Hash function uses Poseidon2 (via dep::poseidon2) for 2-to-1 compression
// - Aligns with on-chain frontier Merkle: H = Poseidon2_2to1 (first limb),
//   zero[0] = 0; zero[i+1] = H(zero[i], zero[i])

use dep::poseidon2;

fn hash2(a: Field, b: Field) -> Field {
    // Poseidon2 2-to-1 hash (BN254 params)
    poseidon2::bn254::hash_2([a, b])
}


fn constrain_bit(bit: Field) {
    // Enforce bit in {0,1}
    assert(bit * (1 - bit) == 0);
}

fn compute_root(leaf: Field, path_siblings: [Field; 20], path_bits: [Field; 20]) -> Field {
    let mut cur = leaf;
    for i in 0..20 {
        let sib = path_siblings[i];
        let bit = path_bits[i];
        constrain_bit(bit);
        let left = bit == 0;
        if left {
            cur = hash2(cur, sib);
        } else {
            cur = hash2(sib, cur);
        }
    }
    cur
}

fn pow2(i: u32) -> Field { let mut v = 1; for _ in 0..i { v = v + v; } v }

fn enforce_index_from_bits(path_bits: [Field; 20], path_index: Field) {
    // Ensure path_index == sum(bits[i] * 2^i)
    let mut acc = 0;
    for i in 0..20 {
        let b = path_bits[i];
        constrain_bit(b);
        acc = acc + b * pow2(i);
    }
    assert(acc == path_index);
}

pub fn main(
    nullifier_hash: pub Field,
    root: pub Field,
    recipient: pub Field,
    nullifier: Field,
    secret: Field,
    path_siblings: [Field; 20],
    path_bits: [Field; 20],
    path_index: Field,
) {
    // Compute commitment and nullifier hash from secrets
    let leaf = hash2(nullifier, secret);
    let nf = hash2(nullifier, 0);

    // Enforce provided public nullifier_hash
    assert(nf == nullifier_hash);

    // Optional: enforce index consistency with bits
    enforce_index_from_bits(path_bits, path_index);

    // Verify Merkle path to public root
    let computed_root = compute_root(leaf, path_siblings, path_bits);
    assert(computed_root == root);
}
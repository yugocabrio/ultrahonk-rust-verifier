// Tornado Classic-style circuit
// - Private inputs: nullifier, secret, Merkle path (siblings, path_bits)
// - Public inputs: root, nullifier_hash
// - Hash function uses Poseidon2 (via dep::poseidon)
// - Aligns with on-chain frontier Merkle: H = Poseidon2_2to1 (first limb),
//   zero[0] = 0; zero[i+1] = H(zero[i], zero[i])

use dep::poseidon::poseidon2::Poseidon2;

fn hash2(a: Field, b: Field) -> Field {
    Poseidon2::hash([a, b], 2)
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

pub fn main(
    root: pub Field,
    nullifier_hash: pub Field,
    nullifier: Field,
    secret: Field,
    path_siblings: [Field; 20],
    path_bits: [Field; 20],
) {
    // Compute commitment and nullifier hash from secrets
    let leaf = hash2(nullifier, secret);
    let nf = hash2(nullifier, 0);

    // Enforce provided public nullifier_hash
    assert(nf == nullifier_hash);

    // Verify Merkle path to public root
    let computed_root = compute_root(leaf, path_siblings, path_bits);
    assert(computed_root == root);

}

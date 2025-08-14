use std::hash::poseidon2::Poseidon2;

pub fn main(secret: Field, blinding: Field, commit: pub Field) {
    let c = Poseidon2::hash([secret, blinding], 2);
    assert(c == commit);
}

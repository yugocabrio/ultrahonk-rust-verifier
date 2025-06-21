use crate::field::Fr;
use hex;

#[inline(always)]
pub fn dbg_fr(tag: &str, x: &Fr) {
    println!("{:<18}: 0x{}", tag, hex::encode(x.to_bytes()));
}
#[inline(always)]
pub fn dbg_vec(tag: &str, xs: &[Fr]) {
    for (i, v) in xs.iter().enumerate() {
        println!("{tag}[{i:02}] = 0x{}", hex::encode(v.to_bytes()), tag = tag, i = i);
    }
}
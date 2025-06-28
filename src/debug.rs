use crate::field::Fr;
use hex;
use ark_ff::{BigInteger256, PrimeField};
use crate::types::G1Point;

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
/// BigInteger256 → 0x プレフィクス付き 64byte 固定幅 16進文字列
#[inline(always)]
fn bigint256_to_hex(b: &BigInteger256) -> String {
    // ark_ff の BigInteger256 は 4×u64 little-endian
    // ここでは BE 表示に揃える
    let limbs_be = b.0.iter().rev();                      // 逆順で BE
    let mut s = String::from("0x");
    for limb in limbs_be {
        s.push_str(&format!("{:016x}", limb));
    }
    s
}

/// ark_bn254::Fr → 16進文字列
#[inline(always)]
pub fn fr_to_hex(fr: &Fr) -> String {
    bigint256_to_hex(&fr.0.into_bigint())
}

/// G1Point → (x,y)16進文字列
#[inline(always)]
pub fn g1_to_hex(pt: &G1Point) -> (String, String) {
    (
        bigint256_to_hex(&pt.x.into_bigint()),
        bigint256_to_hex(&pt.y.into_bigint()),
    )
}

/// coms / scalars を "TS ログ互換" フォーマットで全部出す
///
/// * `head_tail` : 省略せず全部出したい場合は `usize::MAX` を渡す
///                 それ以外は「先頭 `head_tail` 件＋末尾 `head_tail` 件」を出力し
///                 中央部は "..." 行で畳みます。
pub fn dump_pairs(coms: &[G1Point], scalars: &[Fr], head_tail: usize) {
    assert_eq!(
        coms.len(),
        scalars.len(),
        "commitment / scalar length mismatch"
    );

    let len = coms.len();
    println!("========= FULL LIST =========");
    for i in 0..len {
        // 範囲外は折り畳み
        if head_tail != usize::MAX && i >= head_tail && i < len - head_tail {
            if i == head_tail {
                println!("    ..."); // ここだけ一度だけ出力
            }
            continue;
        }

        let (x_hex, y_hex) = g1_to_hex(&coms[i]);
        let s_hex = fr_to_hex(&scalars[i]);

        println!(
            "[#{:02}]  s = {:>66}  C.x = {:>66}  C.y = {:>66}",
            i, s_hex, x_hex, y_hex
        );
    }
    println!("================================");
}
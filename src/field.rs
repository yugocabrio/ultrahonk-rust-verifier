//! Finite-field wrapper for BN254 Fr, compatible with Arkworks 0.5.

use ark_bn254::Fr as ArkFr;
use ark_ff::{Field, Zero, PrimeField};
use ark_serialize::CanonicalSerialize;
use hex;
use std::ops::{Add, Mul, Neg, Sub};
use ark_ff::BigInteger256;

/*────────────────────────────  OddLength を回避するヘルパ  ──────────────────────────*/
/// "0x…" を剥がし、奇数桁なら先頭に '0' を付けて **必ず偶数桁** にする。
#[inline(always)]
fn normalize_hex(s: &str) -> String {
    let raw = s.trim_start_matches("0x");
    if raw.len() & 1 == 1 {
        let mut out = String::with_capacity(raw.len() + 1);
        out.push('0');
        out.push_str(raw);
        out
    } else {
        raw.to_owned()
    }
}

/*────────────────────────────  Fr wrapper  ──────────────────────────*/

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fr(pub ArkFr);

impl Fr {
    /*--------- constructors ---------*/

    /// Construct from u64.
    pub fn from_u64(x: u64) -> Self {
        Fr(ArkFr::from(x))
    }

    /// Construct from hex string (with or without 0x prefix).
    /// 偶数桁に正規化してから `hex::decode` するので OddLength 例外は起こさない。
    pub fn from_str(s: &str) -> Self {
        let bytes = hex::decode(normalize_hex(s)).expect("hex decode failed");
        let mut padded = [0u8; 32];
        let offset = 32 - bytes.len();
        padded[offset..].copy_from_slice(&bytes);
        Self::from_bytes(&padded)
    }

    /// Construct from a 32-byte big-endian array.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        // ark-ff は LE を取るので BE → LE
        let mut tmp = *bytes;
        tmp.reverse();
        Fr(ArkFr::from_le_bytes_mod_order(&tmp))
    }

    /*--------- conversions ---------*/

    /// Convert to 32-byte big-endian representation.
    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 32] {
        let bi: BigInteger256 = self.0.into_bigint();
        let mut out = [0u8; 32];
        for (i, limb) in bi.0.iter().rev().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    /// Convert to "0x…" hex string（常に 64 桁）— デバッグ用。
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }

    /*--------- math helpers ---------*/

    pub fn inverse(&self) -> Self {
        Fr(self.0.inverse().unwrap())
    }

    pub fn zero() -> Self {
        Fr(ArkFr::zero())
    }

    pub fn one() -> Self {
        Fr(ArkFr::ONE)
    }

    pub fn pow(&self, exp: u128) -> Self {
        let mut bits = [0u64; 4];
        bits[0] = exp as u64;
        Fr(self.0.pow(bits))
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    pub fn div(&self, rhs: &Fr) -> Self {
        Fr(self.0 * rhs.0.inverse().unwrap())
    }
}

/*────────────────────────────  Operators / Serialize  ──────────────────────────*/

impl Add for Fr {
    type Output = Fr;
    fn add(self, rhs: Fr) -> Fr {
        Fr(self.0 + rhs.0)
    }
}

impl Sub for Fr {
    type Output = Fr;
    fn sub(self, rhs: Fr) -> Fr {
        Fr(self.0 - rhs.0)
    }
}

impl Mul for Fr {
    type Output = Fr;
    fn mul(self, rhs: Fr) -> Fr {
        Fr(self.0 * rhs.0)
    }
}

impl Neg for Fr {
    type Output = Fr;
    fn neg(self) -> Fr {
        Fr(-self.0)
    }
}

impl CanonicalSerialize for Fr {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        _compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.0.serialize_compressed(&mut writer)
    }

    fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
        self.0.compressed_size()
    }
}

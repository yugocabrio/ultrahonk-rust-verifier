// field.rs

use ark_bn254::Fr as ArkFr;
use ark_ff::BigInteger256;
use ark_ff::{Field, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use hex;
use std::ops::{Add, Mul, Neg, Sub};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fr(pub ArkFr);

impl Fr {
    /// Construct from u64.
    pub fn from_u64(x: u64) -> Self {
        Fr(ArkFr::from(x))
    }

    /// Construct from hex string (with or without 0x prefix).
    /// Normalize to even digits before `hex::decode` so OddLength exception won't occur.
    pub fn from_str(s: &str) -> Self {
        let bytes = hex::decode(normalize_hex(s)).expect("hex decode failed");
        let mut padded = [0u8; 32];
        let offset = 32 - bytes.len();
        padded[offset..].copy_from_slice(&bytes);
        Self::from_bytes(&padded)
    }

    /// Construct from a 32-byte big-endian array.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        // ark-ff takes LE (little-endian) so BE → LE
        let mut tmp = *bytes;
        tmp.reverse();
        Fr(ArkFr::from_le_bytes_mod_order(&tmp))
    }

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

    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }

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

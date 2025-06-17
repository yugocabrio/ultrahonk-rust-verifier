//! Finite-field wrapper for BN254 Fr, compatible with Arkworks 0.5.

use ark_bn254::Fr as ArkFr;
use ark_ff::{Field, Zero, BigInteger256, PrimeField, BigInteger, FpConfig};
use ark_serialize::{CanonicalSerialize};
use std::ops::{Add, Mul, Neg, Sub};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fr(pub ArkFr);

impl Fr {
    /// Construct from u64.
    pub fn from_u64(x: u64) -> Self {
        Fr(ArkFr::from(x))
    }

    /// Construct from hex string (with or without 0x prefix).
    pub fn from_str(s: &str) -> Self {
        let without_prefix = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(without_prefix).expect("Invalid hex string");
        let mut padded = [0u8; 32];
        let offset = 32 - bytes.len();
        padded[offset..].copy_from_slice(&bytes);
        Self::from_bytes(&padded)
    }

    /// Convert to 32-byte big-endian representation.
    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut le = self.0.into_bigint().to_bytes_le(); // 最低限の長さ
        le.resize(32, 0);                                // 32 byte 埋め
        le.reverse();                                    // LE → BE
        let mut be = [0u8; 32];
        be.copy_from_slice(&le);
        be
    }

    /// Construct from a 32-byte big-endian array.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        // ark-ff は LE で `from_le_bytes_mod_order` を提供しているので
        // BE → LE へ並べ替えて呼び出す
        let mut tmp = *bytes;
        tmp.reverse();                           // BE → LE
        Fr(ArkFr::from_le_bytes_mod_order(&tmp)) // 常に Some を返し mod p 還元も行う
    }


    /// Return multiplicative inverse.
    pub fn inverse(&self) -> Self {
        Fr(self.0.inverse().unwrap())
    }

    /// Return zero.
    pub fn zero() -> Self {
        Fr(ArkFr::zero())
    }

    /// Return one.
    pub fn one() -> Self {
        Fr(ArkFr::ONE)
    }

    /// Exponentiation.
    pub fn pow(&self, exp: u128) -> Self {
        let mut bits = [0u64; 4];
        bits[0] = exp as u64;
        Fr(self.0.pow(bits))
    }

    /// Check if zero.
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Divide by another Fr.
    pub fn div(&self, rhs: &Fr) -> Self {
        Fr(self.0 * rhs.0.inverse().unwrap())
    }
}

// Arithmetic ops
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
        _compress: ark_serialize::Compress
    ) -> Result<(), ark_serialize::SerializationError> {
        self.0.serialize_compressed(&mut writer)
    }

    fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
        self.0.compressed_size()
    }
}

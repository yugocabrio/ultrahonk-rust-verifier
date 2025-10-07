#![allow(clippy::needless_range_loop)]

use num_bigint::BigUint;
use std::str::FromStr;

// BN254 prime modulus
const P: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";

#[derive(Debug, Clone, Copy, PartialEq)]
struct Fq {
    value: [u64; 4], // Little-endian representation
}

impl Fq {
    const ZERO: Self = Self { value: [0, 0, 0, 0] };
    const ONE: Self = Self { value: [1, 0, 0, 0] };

    fn from_u64(n: u64) -> Self {
        Self {
            value: [n, 0, 0, 0],
        }
    }

    fn from_hex(hex: &str) -> Self {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let big = BigUint::parse_bytes(hex.as_bytes(), 16).expect("Invalid hex");
        let p = BigUint::from_str(P).unwrap();
        let reduced = big % p;
        
        let bytes = reduced.to_bytes_le();
        let mut value = [0u64; 4];
        
        for (i, chunk) in bytes.chunks(8).enumerate() {
            if i >= 4 { break; }
            let mut word = 0u64;
            for (j, &byte) in chunk.iter().enumerate() {
                word |= (byte as u64) << (j * 8);
            }
            value[i] = word;
        }
        
        Self { value }
    }

    fn to_hex(&self) -> String {
        let mut bytes = Vec::new();
        for &word in self.value.iter() {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        
        // Remove trailing zeros
        while bytes.len() > 1 && bytes.last() == Some(&0) {
            bytes.pop();
        }
        
        let big = BigUint::from_bytes_le(&bytes);
        format!("0x{:x}", big)
    }

    fn add(self, other: Self) -> Self {
        // Simple addition using BigUint for correctness
        let a = self.to_biguint();
        let b = other.to_biguint();
        let p = BigUint::from_str(P).unwrap();
        let result = (a + b) % p;
        Self::from_biguint(result)
    }

    fn mul(self, other: Self) -> Self {
        let a = self.to_biguint();
        let b = other.to_biguint();
        let p = BigUint::from_str(P).unwrap();
        let result = (a * b) % p;
        Self::from_biguint(result)
    }

    fn pow5(self) -> Self {
        let x2 = self.mul(self);
        let x4 = x2.mul(x2);
        x4.mul(self)
    }

    fn to_biguint(self) -> BigUint {
        let mut bytes = Vec::new();
        for &word in self.value.iter() {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        BigUint::from_bytes_le(&bytes)
    }

    fn from_biguint(big: BigUint) -> Self {
        let bytes = big.to_bytes_le();
        let mut value = [0u64; 4];
        
        for (i, chunk) in bytes.chunks(8).enumerate() {
            if i >= 4 { break; }
            let mut word = 0u64;
            for (j, &byte) in chunk.iter().enumerate() {
                word |= (byte as u64) << (j * 8);
            }
            value[i] = word;
        }
        
        Self { value }
    }

    fn from_be_bytes_mod_p(bytes: &[u8; 32]) -> Self {
        let big = BigUint::from_bytes_be(bytes);
        let p = BigUint::from_str(P).unwrap();
        let reduced = big % p;
        Self::from_biguint(reduced)
    }

    fn to_be_bytes32(self) -> [u8; 32] {
        let big = self.to_biguint();
        let mut be = big.to_bytes_be();
        if be.len() > 32 {
            be = be[be.len() - 32..].to_vec();
        }
        let mut out = [0u8; 32];
        let start = 32 - be.len();
        out[start..].copy_from_slice(&be);
        out
    }
}

impl std::ops::Add for Fq {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        self.add(rhs)
    }
}

impl std::ops::Mul for Fq {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        self.mul(rhs)
    }
}

impl std::ops::AddAssign for Fq {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

#[inline(always)]
fn sbox2(state: &mut [Fq; 2]) {
    state[0] = state[0].pow5();
    state[1] = state[1].pow5();
}

#[inline(always)]
fn sbox_e(x: Fq) -> Fq {
    x.pow5()
}

// t=2 external mix: [a+sum, b+sum] where sum=a+b
#[inline(always)]
fn external_2(state: [Fq; 2]) -> [Fq; 2] {
    let sum = state[0] + state[1];
    [state[0] + sum, state[1] + sum]
}

// t=2 internal mix: [x+sum, 2*y + sum] where sum=x+y
#[inline(always)]
fn internal_2(state: [Fq; 2]) -> [Fq; 2] {
    let x = state[0];
    let y = state[1];
    let sum = x + y;
    [x + sum, sum + y + y]
}

// Round constants
const FIRST_FULL_RC_HEX: [[&str; 2]; 4] = [
    [
        "0x09c46e9ec68e9bd4fe1faaba294cba38a71aa177534cdd1b6c7dc0dbd0abd7a7",
        "0x0c0356530896eec42a97ed937f3135cfc5142b3ae405b8343c1d83ffa604cb81",
    ],
    [
        "0x1e28a1d935698ad1142e51182bb54cf4a00ea5aabd6268bd317ea977cc154a30",
        "0x27af2d831a9d2748080965db30e298e40e5757c3e008db964cf9e2b12b91251f",
    ],
    [
        "0x1e6f11ce60fc8f513a6a3cfe16ae175a41291462f214cd0879aaf43545b74e03",
        "0x2a67384d3bbd5e438541819cb681f0be04462ed14c3613d8f719206268d142d3",
    ],
    [
        "0x0b66fdf356093a611609f8e12fbfecf0b985e381f025188936408f5d5c9f45d0",
        "0x012ee3ec1e78d470830c61093c2ade370b26c83cc5cebeeddaa6852dbdb09e21",
    ],
];

const PARTIAL_HEX: &[&str] = &[
    "0x0252ba5f6760bfbdfd88f67f8175e3fd6cd1c431b099b6bb2d108e7b445bb1b9",
    "0x179474cceca5ff676c6bec3cef54296354391a8935ff71d6ef5aeaad7ca932f1",
    "0x2c24261379a51bfa9228ff4a503fd4ed9c1f974a264969b37e1a2589bbed2b91",
    "0x1cc1d7b62692e63eac2f288bd0695b43c2f63f5001fc0fc553e66c0551801b05",
    "0x255059301aada98bb2ed55f852979e9600784dbf17fbacd05d9eff5fd9c91b56",
    "0x28437be3ac1cb2e479e1f5c0eccd32b3aea24234970a8193b11c29ce7e59efd9",
    "0x28216a442f2e1f711ca4fa6b53766eb118548da8fb4f78d4338762c37f5f2043",
    "0x2c1f47cd17fa5adf1f39f4e7056dd03feee1efce03094581131f2377323482c9",
    "0x07abad02b7a5ebc48632bcc9356ceb7dd9dafca276638a63646b8566a621afc9",
    "0x0230264601ffdf29275b33ffaab51dfe9429f90880a69cd137da0c4d15f96c3c",
    "0x1bc973054e51d905a0f168656497ca40a864414557ee289e717e5d66899aa0a9",
    "0x2e1c22f964435008206c3157e86341edd249aff5c2d8421f2a6b22288f0a67fc",
    "0x1224f38df67c5378121c1d5f461bbc509e8ea1598e46c9f7a70452bc2bba86b8",
    "0x02e4e69d8ba59e519280b4bd9ed0068fd7bfe8cd9dfeda1969d2989186cde20e",
    "0x1f1eccc34aaba0137f5df81fc04ff3ee4f19ee364e653f076d47e9735d98018e",
    "0x1672ad3d709a353974266c3039a9a7311424448032cd1819eacb8a4d4284f582",
    "0x283e3fdc2c6e420c56f44af5192b4ae9cda6961f284d24991d2ed602df8c8fc7",
    "0x1c2a3d120c550ecfd0db0957170fa013683751f8fdff59d6614fbd69ff394bcc",
    "0x216f84877aac6172f7897a7323456efe143a9a43773ea6f296cb6b8177653fbd",
    "0x2c0d272becf2a75764ba7e8e3e28d12bceaa47ea61ca59a411a1f51552f94788",
    "0x16e34299865c0e28484ee7a74c454e9f170a5480abe0508fcb4a6c3d89546f43",
    "0x175ceba599e96f5b375a232a6fb9cc71772047765802290f48cd939755488fc5",
    "0x0c7594440dc48c16fead9e1758b028066aa410bfbc354f54d8c5ffbb44a1ee32",
    "0x1a3c29bc39f21bb5c466db7d7eb6fd8f760e20013ccf912c92479882d919fd8d",
    "0x0ccfdd906f3426e5c0986ea049b253400855d349074f5a6695c8eeabcd22e68f",
    "0x14f6bc81d9f186f62bdb475ce6c9411866a7a8a3fd065b3ce0e699b67dd9e796",
    "0x0962b82789fb3d129702ca70b2f6c5aacc099810c9c495c888edeb7386b97052",
    "0x1a880af7074d18b3bf20c79de25127bc13284ab01ef02575afef0c8f6a31a86d",
    "0x10cba18419a6a332cd5e77f0211c154b20af2924fc20ff3f4c3012bb7ae9311b",
    "0x057e62a9a8f89b3ebdc76ba63a9eaca8fa27b7319cae3406756a2849f302f10d",
    "0x287c971de91dc0abd44adf5384b4988cb961303bbf65cff5afa0413b44280cee",
    "0x21df3388af1687bbb3bca9da0cca908f1e562bc46d4aba4e6f7f7960e306891d",
    "0x1be5c887d25bce703e25cc974d0934cd789df8f70b498fd83eff8b560e1682b3",
    "0x268da36f76e568fb68117175cea2cd0dd2cb5d42fda5acea48d59c2706a0d5c1",
    "0x0e17ab091f6eae50c609beaf5510ececc5d8bb74135ebd05bd06460cc26a5ed6",
    "0x04d727e728ffa0a67aee535ab074a43091ef62d8cf83d270040f5caa1f62af40",
    "0x0ddbd7bf9c29341581b549762bc022ed33702ac10f1bfd862b15417d7e39ca6e",
    "0x2790eb3351621752768162e82989c6c234f5b0d1d3af9b588a29c49c8789654b",
    "0x1e457c601a63b73e4471950193d8a570395f3d9ab8b2fd0984b764206142f9e9",
    "0x21ae64301dca9625638d6ab2bbe7135ffa90ecd0c43ff91fc4c686fc46e091b0",
    "0x0379f63c8ce3468d4da293166f494928854be9e3432e09555858534eed8d350b",
    "0x002d56420359d0266a744a080809e054ca0e4921a46686ac8c9f58a324c35049",
    "0x123158e5965b5d9b1d68b3cd32e10bbeda8d62459e21f4090fc2c5af963515a6",
    "0x0be29fc40847a941661d14bbf6cbe0420fbb2b6f52836d4e60c80eb49cad9ec1",
    "0x1ac96991dec2bb0557716142015a453c36db9d859cad5f9a233802f24fdf4c1a",
    "0x1596443f763dbcc25f4964fc61d23b3e5e12c9fa97f18a9251ca3355bcb0627e",
    "0x12e0bcd3654bdfa76b2861d4ec3aeae0f1857d9f17e715aed6d049eae3ba3212",
    "0x0fc92b4f1bbea82b9ea73d4af9af2a50ceabac7f37154b1904e6c76c7cf964ba",
    "0x1f9c0b1610446442d6f2e592a8013f40b14f7c7722236f4f9c7e965233872762",
    "0x0ebd74244ae72675f8cde06157a782f4050d914da38b4c058d159f643dbbf4d3",
    "0x2cb7f0ed39e16e9f69a9fafd4ab951c03b0671e97346ee397a839839dccfc6d1",
    "0x1a9d6e2ecff022cc5605443ee41bab20ce761d0514ce526690c72bca7352d9bf",
    "0x2a115439607f335a5ea83c3bc44a9331d0c13326a9a7ba3087da182d648ec72f",
    "0x23f9b6529b5d040d15b8fa7aee3e3410e738b56305cd44f29535c115c5a4c060",
    "0x05872c16db0f72a2249ac6ba484bb9c3a3ce97c16d58b68b260eb939f0e6e8a7",
    "0x1300bdee08bb7824ca20fb80118075f40219b6151d55b5c52b624a7cdeddf6a7",
];

const SECOND_FULL_RC_HEX: [[&str; 2]; 4] = [
    [
        "0x19b9b63d2f108e17e63817863a8f6c288d7ad29916d98cb1072e4e7b7d52b376",
        "0x015bee1357e3c015b5bda237668522f613d1c88726b5ec4224a20128481b4f7f",
    ],
    [
        "0x2953736e94bb6b9f1b9707a4f1615e4efe1e1ce4bab218cbea92c785b128ffd1",
        "0x0b069353ba091618862f806180c0385f851b98d372b45f544ce7266ed6608dfc",
    ],
    [
        "0x304f74d461ccc13115e4e0bcfb93817e55aeb7eb9306b64e4f588ac97d81f429",
        "0x15bbf146ce9bca09e8a33f5e77dfe4f5aad2a164a4617a4cb8ee5415cde913fc",
    ],
    [
        "0x0ab4dfe0c2742cde44901031487964ed9b8f4b850405c10ca9ff23859572c8c6",
        "0x0e32db320a044e3197f45f7649a19675ef5eedfea546dea9251de39f9639779a",
    ],
];

/// Poseidon2 t=2 permutation
pub fn permute_2(mut state: [Fq; 2]) -> [Fq; 2] {
    // initial external mix
    state = external_2(state);

    // first 4 full rounds
    for r in 0..4 {
        state[0] += Fq::from_hex(FIRST_FULL_RC_HEX[r][0]);
        state[1] += Fq::from_hex(FIRST_FULL_RC_HEX[r][1]);
        sbox2(&mut state);
        state = external_2(state);
    }

    // 56 partial rounds
    for &rc_hex in PARTIAL_HEX.iter() {
        state[0] += Fq::from_hex(rc_hex);
        state[0] = sbox_e(state[0]);
        state = internal_2(state);
    }

    // final 4 full rounds
    for r in 0..4 {
        state[0] += Fq::from_hex(SECOND_FULL_RC_HEX[r][0]);
        state[1] += Fq::from_hex(SECOND_FULL_RC_HEX[r][1]);
        sbox2(&mut state);
        state = external_2(state);
    }

    state
}

/// Convenience: Poseidon2 hash2 compatible compressor output (first limb) from 32-byte BE inputs
pub fn permute_2_bytes_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let s0 = Fq::from_be_bytes_mod_p(a);
    let s1 = Fq::from_be_bytes_mod_p(b);
    let out = permute_2([s0, s1]);
    out[0].to_be_bytes32()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t2_fixtures() {
        let out = permute_2([Fq::from_hex("0x0"), Fq::from_hex("0x1")]);
        assert_eq!(out[0], Fq::from_hex("0x1d01e56f49579cec72319e145f06f6177f6c5253206e78c2689781452a31878b"));
        assert_eq!(out[1], Fq::from_hex("0x0d189ec589c41b8cffa88cfc523618a055abe8192c70f75aa72fc514560f6c61"));

        let out = permute_2([
            Fq::from_hex("0x0ae097f5ad29d8a8329dc964d961c9933a57667122baa88351719021510aadcc"),
            Fq::from_hex("0x1db0afb64a7847b404e509b8076ea6f113e0dc33c8d8923850288b297b366a96"),
        ]);
        assert_eq!(out[0], Fq::from_hex("0x234411a64c9117a670dcbb2e32887c05695108becb3746a4b63a5e0c64abf213"));
        assert_eq!(out[1], Fq::from_hex("0x0aeacd239c8086b9199880f4c20576cab326b06c4692d3dec9e13a35228a2a47"));

        let out = permute_2([
            Fq::from_hex("0x190e9f8d74c3ee7e6f9a5fc4f3e9aea43e4c636652d64732663ce4d4e9a82dfc"),
            Fq::from_hex("0x116d4666591fd484d3f63b2143851ecf51790d344f076703aff0ea2ae73d84c0"),
        ]);
        assert_eq!(out[0], Fq::from_hex("0x184f08154e7c0ae8d1dd611de726a33b46e83c881e7dcc83969ab5225bb1ffd2"));
        assert_eq!(out[1], Fq::from_hex("0x1c869eaf711604998e0015346275a1df87c872497cf501796b5c665bac5e6c51"));

        let out = permute_2([
            Fq::from_hex("0x0765449fba54a8f027fdfc4bba2251e13867d2999658961503e1c552eb8d30f0"),
            Fq::from_hex("0x2458fc60fe06af665be546da89f792db27ba8122735483b028f7945b79a0121d"),
        ]);
        assert_eq!(out[0], Fq::from_hex("0x00b99fef7542031ec0fc94e798c29b8d270ae80b0496316c722f149ddbd24c10"));
        assert_eq!(out[1], Fq::from_hex("0x05a9add2dfce4303c28124e1165154fcf44b7784d3adcc56f505d4e5917b8096"));

        let out = permute_2([
            Fq::from_hex("0x05df817f34e9cc11af435dd58951c0dc120a9637f1625dae110c900fd64fac01"),
            Fq::from_hex("0x165798534b555615e2d3a7c0371d7c6b37814e4816dfcbcce9a7f5134166bf95"),
        ]);
        assert_eq!(out[0], Fq::from_hex("0x2383496930a272a7d99e2db4dcfbe427ac7ece01dbb2c74e0393f44807131987"));
        assert_eq!(out[1], Fq::from_hex("0x238c2be5f5769977c50e089de45933dc1a00ef4f451497fa67b880fcbb5086da"));

        let out = permute_2([
            Fq::from_hex("0x278ab5ceb7ccf50051df09e958a60cdc29304d5a8bc5f512e8c05e4e8344b494"),
            Fq::from_hex("0x0691450210975cfd5ad15ad9b7b8d2c0b0e15bc964511530830691b9bdb1deab"),
        ]);
        assert_eq!(out[0], Fq::from_hex("0x267529bf7c33acceb53850eba2b713f4449a04d168f90b211c9cbfc2977955e8"));
        assert_eq!(out[1], Fq::from_hex("0x0dd91eb3904b8fd295abae96ce1e387d3ce1c06f1e68b8b14567c283a2719c10"));

        let out = permute_2([
            Fq::from_hex("0x0c19d1ab43ce3d913418687b4a60b758e2be814434c5310c7f0a6f5813befa40"),
            Fq::from_hex("0x0cff2930faece292fb8ef0447faa51eca7538b91999d308c914ffe166deae4b2"),
        ]);
        assert_eq!(out[0], Fq::from_hex("0x1ac275a60d969f95feead488e81955aa70680121066220a8e313309e76ce8c59"));
        assert_eq!(out[1], Fq::from_hex("0x05119d1c349bf5ad1b9af9ca6f17c40cd378cf971125709f1905b68d5172826c"));

        let out = permute_2([
            Fq::from_hex("0x23b96a10b3a6b5cb32a4a48ba9e2c7fd95a0381977051d377aba654ce3f46d3f"),
            Fq::from_hex("0x12c4411263a01236387f3ad010243a44ac532a834589d6d7a38a0149748bf187"),
        ]);
        assert_eq!(out[0], Fq::from_hex("0x26603ba36cd41bdbde16e06c6f1ec040743059b6ce45fe6f34e00bcb6e535b04"));
        assert_eq!(out[1], Fq::from_hex("0x0301f7923f6d373b7a36ce42a8f8be025d3f88e0abcd0b54e78ebfbf9116a9bf"));

        let out = permute_2([
            Fq::from_hex("0x2f1df4234732c49ac7567c29d2e066308f807e1bbf0951136b7fccba2602ea9e"),
            Fq::from_hex("0x04a23083267080ae4ee1a3cb4173dbce507c86edcfdd02853b0399cdab611517"),
        ]);
        assert_eq!(out[0], Fq::from_hex("0x0d6e20ac92800c7b08438805fe94a871c5f756ec07a919923c4e007cf01fa87e"));
        assert_eq!(out[1], Fq::from_hex("0x0d0e60f1acb65d948e7ff874e255c2c07a0f0ecc15e4d14209bc5d5715951ccb"));

        let out = permute_2([
            Fq::from_hex("0x106babe89343a47ce296eed78129b6f7af056b46ad808b2cabb66f371180dd17"),
            Fq::from_hex("0x2f01d999b6e58284d87640c08c49e96d538ba3ffba0c544090fe858dbb5bc28e"),
        ]);
        assert_eq!(out[0], Fq::from_hex("0x08d523548b9f396c877536b5f96fdfd1826ecdc0c806e24ae328586e8a405d8f"));
        assert_eq!(out[1], Fq::from_hex("0x1c1c5eeb613b596dd524fe59264ae5ef173cbd271e7f476a5f15d56175cb7478"));

        let out = permute_2([
            Fq::from_hex("0x299c0a40411ed9d7de7792fa299b262937b21fabfa386fa761e3f079c1d9045f"),
            Fq::from_hex("0x2ace2e81e39d97a8e6d83c9e50a8643f4bf01a1465177518558305e7ab254c62"),
        ]);
        assert_eq!(out[0], Fq::from_hex("0x2c62b5c08ee75aa967809de58131cb38e953fdbdccb9140ed92ea89adebcda85"));
        assert_eq!(out[1], Fq::from_hex("0x2c507b864995a399f7c1143f8c9dc67b7aca63419a2443a879715404a16ec6b8"));
    }
}

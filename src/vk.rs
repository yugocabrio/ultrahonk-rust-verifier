use alloc::vec::Vec as StdVec;
use ark_bn254::{Fq, G1Affine as ArkG1Affine};
use ark_ff::{PrimeField, Zero};
use ultrahonk_rust_verifier::{
    types::{G1Point, VerificationKey},
    utils::load_vk_from_json,
};

const VK_HEADER_WORDS: usize = 4;
const VK_NUM_G1_POINTS: usize = 28;
pub const VK_SERIALIZED_LEN: usize = VK_HEADER_WORDS * 8 + VK_NUM_G1_POINTS * 64;

/// 32-byte big-endian → Fq
#[inline(always)]
fn fq_from_be_bytes(bytes_be: &[u8; 32]) -> Fq {
    Fq::from_be_bytes_mod_order(bytes_be)
}

/// Fq → 32-byte big-endian
#[inline(always)]
fn fq_to_be_bytes(value: &Fq) -> [u8; 32] {
    use ark_ff::BigInteger;

    let mut out = [0u8; 32];
    let bytes = (*value).into_bigint().to_bytes_be();
    let offset = 32 - bytes.len();
    out[offset..].copy_from_slice(&bytes);
    out
}

fn g1_bytes_to_affine(bytes: &[u8; 64]) -> Result<ArkG1Affine, ()> {
    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&bytes[..32]);
    y_bytes.copy_from_slice(&bytes[32..]);
    let aff = ArkG1Affine::new_unchecked(fq_from_be_bytes(&x_bytes), fq_from_be_bytes(&y_bytes));
    if aff.is_on_curve() && aff.is_in_correct_subgroup_assuming_on_curve() {
        Ok(aff)
    } else {
        Err(())
    }
}

fn g1_point_from_bytes(bytes: &[u8; 64]) -> Result<G1Point, ()> {
    if bytes.iter().all(|b| *b == 0) {
        return Ok(G1Point {
            x: Fq::from(0u64),
            y: Fq::from(0u64),
        });
    }
    let aff = g1_bytes_to_affine(bytes)?;
    Ok(G1Point { x: aff.x, y: aff.y })
}

fn g1_point_to_bytes(pt: &G1Point) -> [u8; 64] {
    if pt.x.is_zero() && pt.y.is_zero() {
        return [0u8; 64];
    }
    let aff = pt.to_affine();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&fq_to_be_bytes(&aff.x));
    out[32..].copy_from_slice(&fq_to_be_bytes(&aff.y));
    out
}

pub fn serialize_vk_to_bytes(vk: &VerificationKey) -> StdVec<u8> {
    let mut out = StdVec::with_capacity(VK_SERIALIZED_LEN);
    let header = [
        vk.circuit_size,
        vk.log_circuit_size,
        vk.public_inputs_size,
        vk.pub_inputs_offset,
    ];
    for &word in &header {
        out.extend_from_slice(&word.to_be_bytes());
    }

    macro_rules! push_point {
        ($pt:expr) => {{
            let bytes = g1_point_to_bytes(&$pt);
            out.extend_from_slice(&bytes);
        }};
    }

    push_point!(vk.qm);
    push_point!(vk.qc);
    push_point!(vk.ql);
    push_point!(vk.qr);
    push_point!(vk.qo);
    push_point!(vk.q4);
    push_point!(vk.q_lookup);
    push_point!(vk.q_arith);
    push_point!(vk.q_delta_range);
    push_point!(vk.q_elliptic);
    push_point!(vk.q_memory);
    push_point!(vk.q_nnf);
    push_point!(vk.q_poseidon2_external);
    push_point!(vk.q_poseidon2_internal);
    push_point!(vk.s1);
    push_point!(vk.s2);
    push_point!(vk.s3);
    push_point!(vk.s4);
    push_point!(vk.id1);
    push_point!(vk.id2);
    push_point!(vk.id3);
    push_point!(vk.id4);
    push_point!(vk.t1);
    push_point!(vk.t2);
    push_point!(vk.t3);
    push_point!(vk.t4);
    push_point!(vk.lagrange_first);
    push_point!(vk.lagrange_last);

    out
}

pub fn deserialize_vk_from_bytes(bytes: &[u8]) -> Result<VerificationKey, ()> {
    if bytes.len() != VK_SERIALIZED_LEN {
        return Err(());
    }
    let mut idx = 0usize;
    fn read_u64(bytes: &[u8], idx: &mut usize) -> u64 {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes[*idx..*idx + 8]);
        *idx += 8;
        u64::from_be_bytes(arr)
    }
    fn read_point(bytes: &[u8], idx: &mut usize) -> Result<G1Point, ()> {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes[*idx..*idx + 64]);
        *idx += 64;
        g1_point_from_bytes(&arr)
    }

    let circuit_size = read_u64(bytes, &mut idx);
    let log_circuit_size = read_u64(bytes, &mut idx);
    let public_inputs_size = read_u64(bytes, &mut idx);
    let pub_inputs_offset = read_u64(bytes, &mut idx);

    macro_rules! next_point {
        () => {
            read_point(bytes, &mut idx)?
        };
    }

    Ok(VerificationKey {
        circuit_size,
        log_circuit_size,
        public_inputs_size,
        pub_inputs_offset,
        qm: next_point!(),
        qc: next_point!(),
        ql: next_point!(),
        qr: next_point!(),
        qo: next_point!(),
        q4: next_point!(),
        q_lookup: next_point!(),
        q_arith: next_point!(),
        q_delta_range: next_point!(),
        q_elliptic: next_point!(),
        q_memory: next_point!(),
        q_nnf: next_point!(),
        q_poseidon2_external: next_point!(),
        q_poseidon2_internal: next_point!(),
        s1: next_point!(),
        s2: next_point!(),
        s3: next_point!(),
        s4: next_point!(),
        id1: next_point!(),
        id2: next_point!(),
        id3: next_point!(),
        id4: next_point!(),
        t1: next_point!(),
        t2: next_point!(),
        t3: next_point!(),
        t4: next_point!(),
        lagrange_first: next_point!(),
        lagrange_last: next_point!(),
    })
}

pub fn preprocess_vk_json(vk_json: &str) -> Result<StdVec<u8>, ()> {
    let vk = load_vk_from_json(vk_json);
    Ok(serialize_vk_to_bytes(&vk))
}

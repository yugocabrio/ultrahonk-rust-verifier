// src/utils.rs
//! Utilities for loading Proof and VerificationKey, plus byte↔field/point conversion.

use crate::field::Fr;
use crate::types::{G1Point, Proof, VerificationKey};
use ark_bn254::{Fq, G1Affine};
use ark_ff::{BigInteger256, PrimeField};
use num_bigint::BigUint;
use num_traits::Num;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "std")]
use std::fs;
#[cfg(feature = "std")]
use std::path::Path;

/// BigUint -> Fq by LE bytes (auto-reduced mod p)
fn biguint_to_fq_mod(x: &BigUint) -> Fq {
    let le = x.to_bytes_le();
    Fq::from_le_bytes_mod_order(&le)
}

/// Convert 32 bytes into an Fr.
fn bytes_to_fr(bytes: &[u8; 32]) -> Fr {
    Fr::from_bytes(bytes)
}

/// Big-Endian 32 byte → Fq (accept mod p)
fn fq_from_be_bytes(bytes_be: &[u8; 32]) -> Fq {
    let mut bytes_le = *bytes_be; // 32-byte copy
    bytes_le.reverse(); // BE → LE
    Fq::from_le_bytes_mod_order(&bytes_le)
}

/// Fq → 32-byte big-endian
pub fn fq_to_be_bytes(f: &Fq) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bi: BigInteger256 = (*f).into(); // 4 × 64-bit limbs (LE)
    for (i, limb) in bi.0.iter().rev().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

/// Fq → (low136, high(<=118)) each 32-byte BE
pub fn fq_to_halves_be(f: &Fq) -> ([u8; 32], [u8; 32]) {
    let be = fq_to_be_bytes(f);
    let big = BigUint::from_bytes_be(&be);
    let mask = (BigUint::from(1u8) << 136) - 1u8; // 2^136 − 1
    let low = &big & &mask; // lower 136 bits
    let high = &big >> 136; // upper bits

    fn to_arr(x: BigUint) -> [u8; 32] {
        let mut arr = [0u8; 32];
        let bytes = x.to_bytes_be();
        arr[32 - bytes.len()..].copy_from_slice(&bytes);
        arr
    }

    (to_arr(low), to_arr(high))
}

// (v0.87) G1 座標は (lo136, hi<=118) の 2 リムで (x,y) を順に格納する前提

/// Load a Proof from a byte array (e.g. read from proof.bin).
pub fn load_proof(proof_bytes: &[u8]) -> Proof {
    let mut cursor = 0usize;

    // Helper: read next 128 bytes as G1Point using 136-bit limb split (x = x0 | (x1<<136))
    fn read_g1(bytes: &[u8], cur: &mut usize) -> G1Point {
        use num_bigint::BigUint;
        let x0 = BigUint::from_bytes_be(&bytes[*cur..*cur + 32]);
        let x1 = BigUint::from_bytes_be(&bytes[*cur + 32..*cur + 64]);
        let y0 = BigUint::from_bytes_be(&bytes[*cur + 64..*cur + 96]);
        let y1 = BigUint::from_bytes_be(&bytes[*cur + 96..*cur + 128]);
        *cur += 128;
        let shift = 136u32;
        let bx = &x0 | (&x1 << shift);
        let by = &y0 | (&y1 << shift);
        let fx = biguint_to_fq_mod(&bx);
        let fy = biguint_to_fq_mod(&by);
        G1Point { x: fx, y: fy }
    }

    // Helper: read next 32 bytes as Fr
    fn read_fr(bytes: &[u8], cur: &mut usize) -> Fr {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[*cur..*cur + 32]);
        *cur += 32;
        bytes_to_fr(&arr)
    }

    // 0) pairing point object: 16 Fr elements
    let mut pairing_point_object = Vec::with_capacity(16);
    for _ in 0..16 {
        pairing_point_object.push(read_fr(proof_bytes, &mut cursor));
    }

    // 1) w1, w2, w3
    let w1 = read_g1(proof_bytes, &mut cursor);
    let w2 = read_g1(proof_bytes, &mut cursor);
    let w3 = read_g1(proof_bytes, &mut cursor);

    // 2) lookup_read_counts, lookup_read_tags
    let lookup_read_counts = read_g1(proof_bytes, &mut cursor);
    let lookup_read_tags = read_g1(proof_bytes, &mut cursor);

    // 3) w4
    let w4 = read_g1(proof_bytes, &mut cursor);

    // 4) lookup_inverses, z_perm
    let lookup_inverses = read_g1(proof_bytes, &mut cursor);
    let z_perm = read_g1(proof_bytes, &mut cursor);

    // 5) sumcheck_univariates: 28 rounds × 8 Fr each
    let mut sumcheck_univariates = Vec::new();
    for _ in 0..28 {
        let mut row = Vec::with_capacity(8);
        for _ in 0..8 {
            row.push(read_fr(proof_bytes, &mut cursor));
        }
        sumcheck_univariates.push(row);
    }

    // 6) sumcheck_evaluations: 40/41 をファイル長から自動判定
    let mut sumcheck_evaluations = Vec::new();
    let size_40 = 16 * 32 /*pairing*/
        + 8 * 128 /*wires & lookups before univariates*/
        + 28 * 8 * 32 /*univariates*/
        + 40 * 32 /*evals*/
        + 27 * 128 /*fold comms*/
        + 28 * 32 /*A evals*/
        + 2 * 128; /*Q + quotient*/
    let evals_to_read = if proof_bytes.len() >= size_40 + 32 { 41 } else { 40 };
    for _ in 0..evals_to_read { sumcheck_evaluations.push(read_fr(proof_bytes, &mut cursor)); }

    // 7) gemini_fold_comms: 27 G1Points
    let mut gemini_fold_comms = Vec::new();
    for _ in 0..27 {
        gemini_fold_comms.push(read_g1(proof_bytes, &mut cursor));
    }

    // 8) gemini_a_evaluations: 28 Fr
    let mut gemini_a_evaluations = Vec::new();
    for _ in 0..28 {
        gemini_a_evaluations.push(read_fr(proof_bytes, &mut cursor));
    }

    // 9) shplonk_q, kzg_quotient
    let shplonk_q = read_g1(proof_bytes, &mut cursor);
    let kzg_quotient = read_g1(proof_bytes, &mut cursor);

    Proof {
        pairing_point_object,
        w1,
        w2,
        w3,
        w4,
        lookup_read_counts,
        lookup_read_tags,
        lookup_inverses,
        z_perm,
        sumcheck_univariates,
        sumcheck_evaluations,
        gemini_fold_comms,
        gemini_a_evaluations,
        shplonk_q,
        kzg_quotient,
    }
}

/// Combine two consecutive 256-bit field elements (each represented as hex string) into a single BigUint.
fn combine_fields(low_str: &str, high_str: &str) -> BigUint {
    // Both strings start with "0x", so strip that.
    let low_hex = low_str.trim_start_matches("0x");
    let high_hex = high_str.trim_start_matches("0x");

    // Parse low/high into BigUint
    let low = BigUint::from_str_radix(low_hex, 16).unwrap();
    let high = BigUint::from_str_radix(high_hex, 16).unwrap();

    // high << (34*4) bits = high << 136

    (high << 136) | low
}

/// Load a VerificationKey from a JSON string containing an array of hex‐encoded field‐elements.
#[cfg(feature = "serde_json")]
pub fn load_vk_from_json(json_data: &str) -> VerificationKey {
    // Parse JSON into Vec<String>
    let vk_fields: Vec<String> = serde_json::from_str(json_data).unwrap();
    // Expect v0.87+ header(3) + 28*4 limbs
    assert!(vk_fields.len() >= 3, "VK JSON must contain header elements");

    // Helper to parse hex field element to u64 (fits for small header values)
    fn parse_u64_hex(s: &str) -> u64 {
        let x = BigUint::from_str_radix(s.trim_start_matches("0x"), 16).unwrap();
        x.to_u64_digits().get(0).copied().unwrap_or(0)
    }

    // Parse VK header (barretenberg v0.87+):
    //   [0] log_circuit_size, [1] num_public_inputs, [2] pub_inputs_offset
    let h0 = parse_u64_hex(&vk_fields[0]);
    let public_inputs_size = if vk_fields.len() > 1 { parse_u64_hex(&vk_fields[1]) } else { 0 };
    let pub_inputs_offset = if vk_fields.len() > 2 { parse_u64_hex(&vk_fields[2]) } else { 0 };
    // 一部のビルドは [0] に circuit_size、別のものは log2(circuit_size) を格納する。
    // 値が 2 の冪なら circuit_size とみなして log を計算、そうでなければ log 値とみなす。
    let (circuit_size_u64, log_circuit_size) = if h0 != 0 && (h0 & (h0 - 1)) == 0 {
        let mut lg = 0u64; let mut n = h0; while n > 1 { n >>= 1; lg += 1; }
        (h0, lg)
    } else {
        let cs = 1u64.checked_shl(h0 as u32).expect("circuit_size too large");
        (cs, h0)
    };

    // Helper to convert BigUint into an Fq via LE bytes (auto-reduced mod p)
    fn biguint_to_fq(x: BigUint) -> Fq { biguint_to_fq_mod(&x) }

    // v0.87 固定: header_len=3, limbs_per_point=4（lo_x, hi_x, lo_y, hi_y）。
    let mut field_index = 3usize;
    // Attempt to auto-synchronize start of G1 limbs in vk_fields.json by sliding until a valid point is found.
    {
        let max_probe = 16usize;
        let len = vk_fields.len();
        'outer: for offset in 0..max_probe {
            if field_index + offset + 3 >= len { break; }
            let ix = field_index + offset;
            let parse = |i: usize| BigUint::from_str_radix(vk_fields[i].trim_start_matches("0x"), 16).unwrap();
            let lx = parse(ix);
            let hx = parse(ix + 1);
            let ly = parse(ix + 2);
            let hy = parse(ix + 3);
            let pt = read_g1_from_limbs(&lx, &hx, &ly, &hy);
            let aff = G1Affine::new_unchecked(pt.x, pt.y);
            if aff.is_on_curve() && aff.is_in_correct_subgroup_assuming_on_curve() {
                field_index = ix;
                break 'outer;
            }
        }
    }

    // Safe reader: 4 limbs → G1 using fixed v0.87 encoding (lo136, hi<=118) per coordinate.
    // Falls back to a couple of alternative assemblies if on-curve check fails.
    fn read_g1_from_limbs(lx: &BigUint, hx: &BigUint, ly: &BigUint, hy: &BigUint) -> G1Point {
        // Primary: lo | (hi << 136)
        let assemble = |lo: &BigUint, hi: &BigUint, shift: u32| -> BigUint { lo | (hi << shift) };
        let mut try_pairs: [([&BigUint; 2], [&BigUint; 2]); 2] = [([lx, hx], [ly, hy]), ([ly, hy], [lx, hx])];
        let shifts = [136u32, 128u32];
        for &shift in &shifts {
            for &(ref ax, ref ay) in &try_pairs {
                let bx = assemble(ax[0], ax[1], shift);
                let by = assemble(ay[0], ay[1], shift);
                let x = biguint_to_fq_mod(&bx);
                let y = biguint_to_fq_mod(&by);
                let aff = G1Affine::new_unchecked(x, y);
                if aff.is_on_curve() && aff.is_in_correct_subgroup_assuming_on_curve() {
                    return G1Point { x: aff.x, y: aff.y };
                }
            }
        }
        G1Point { x: Fq::from(0u64), y: Fq::from(0u64) }
    }

    macro_rules! read_g1 {
        () => {{
            let low_x = &vk_fields[field_index];
            let high_x = &vk_fields[field_index + 1];
            let low_y = &vk_fields[field_index + 2];
            let high_y = &vk_fields[field_index + 3];
            let lx = BigUint::from_str_radix(low_x.trim_start_matches("0x"), 16).unwrap();
            let hx = BigUint::from_str_radix(high_x.trim_start_matches("0x"), 16).unwrap();
            let ly = BigUint::from_str_radix(low_y.trim_start_matches("0x"), 16).unwrap();
            let hy = BigUint::from_str_radix(high_y.trim_start_matches("0x"), 16).unwrap();
            field_index += 4;
            read_g1_from_limbs(&lx, &hx, &ly, &hy)
        }};
    }

    // Follow bb v0.87 vk_fields.json order (wire/commitment order in fields file):
    // qm, qc, ql, qr, qo, q4, q_lookup, q_arith, q_delta_range, q_elliptic, q_memory(qAux),
    // q_poseidon2_external, q_poseidon2_internal, s1..s4, id1..id4, t1..t4, lagrange_first, lagrange_last
    let qm = read_g1!();
    let qc = read_g1!();
    let ql = read_g1!();
    let qr = read_g1!();
    let qo = read_g1!();
    let q4 = read_g1!();
    let q_lookup = read_g1!();
    let q_arith = read_g1!();
    let q_delta_range = read_g1!();
    let q_elliptic = read_g1!();
    let q_memory = read_g1!(); // qAux
    let q_poseidon2_external = read_g1!();
    let q_poseidon2_internal = read_g1!();
    let s1 = read_g1!();
    let s2 = read_g1!();
    let s3 = read_g1!();
    let s4 = read_g1!();
    // bb v0.87 order: IDs come before table commitments
    let id1 = read_g1!();
    let id2 = read_g1!();
    let id3 = read_g1!();
    let id4 = read_g1!();
    let t1 = read_g1!();
    let t2 = read_g1!();
    let t3 = read_g1!();
    let t4 = read_g1!();
    let lagrange_first = read_g1!();
    let lagrange_last = read_g1!();

    VerificationKey {
        circuit_size: circuit_size_u64,
        log_circuit_size,
        public_inputs_size,
        pub_inputs_offset,
        qm,
        qc,
        ql,
        qr,
        qo,
        q4,
        q_lookup,
        q_arith,
        q_delta_range,
        q_elliptic,
        q_memory,
        q_nnf: G1Point { x: Fq::from(0u64), y: Fq::from(0u64) },
        q_poseidon2_external,
        q_poseidon2_internal,
        s1,
        s2,
        s3,
        s4,
        id1,
        id2,
        id3,
        id4,
        t1,
        t2,
        t3,
        t4,
        lagrange_first,
        lagrange_last,
    }
}

/// Load a VerificationKey from a `vk` binary emitted by `bb write_vk --output_format bytes_and_fields`.
/// This parser assumes the `vk` file contains a flat sequence of BN254 G1 affine elements (x||y),
/// each coordinate encoded as 32-byte big-endian field element. If the length does not match an
/// integral number of points, or on-curve checks fail, this function returns None.
#[cfg(feature = "std")]
pub fn load_vk_from_bytes_file(path: &Path) -> Option<VerificationKey> {
    let data = fs::read(path).ok()?;
    // Some builds prefix with 32 bytes; strip if present to align to 64-byte records
    let offset = if data.len() % 64 == 32 { 32 } else { 0 };
    if (data.len() - offset) % 64 != 0 { return None; }
    let npts = (data.len() - offset) / 64;
    if npts < 27 || npts > 28 { return None; }
    let mut idx = offset;
    let mut read_xy = || -> Option<G1Point> {
        if idx + 64 > data.len() { return None; }
        let mut xb = [0u8; 32];
        let mut yb = [0u8; 32];
        xb.copy_from_slice(&data[idx..idx + 32]);
        yb.copy_from_slice(&data[idx + 32..idx + 64]);
        idx += 64;
        let x = fq_from_be_bytes(&xb);
        let y = fq_from_be_bytes(&yb);
        let aff = G1Affine::new_unchecked(x, y);
        if !(aff.is_on_curve() && aff.is_in_correct_subgroup_assuming_on_curve()) {
            return None;
        }
        Some(G1Point { x: aff.x, y: aff.y })
    };

    // Read all points in file order first
    let mut raw_points: Vec<G1Point> = Vec::with_capacity(npts);
    for _ in 0..npts { raw_points.push(read_xy()?); }

    // If a JSON VK is present, use it to infer the label mapping by matching points
    let mut mapped = None;
    if let Ok(json_txt) = fs::read_to_string(path.with_file_name("vk_fields.json")) {
        #[allow(unused_mut)]
        if let Ok(_probe) = serde_json::from_str::<Vec<String>>(&json_txt) {
            let ref_vk = load_vk_from_json(&json_txt);
            let ref_list: [(&str, &G1Point); 28] = [
                ("ql", &ref_vk.ql),
                ("qr", &ref_vk.qr),
                ("qo", &ref_vk.qo),
                ("q4", &ref_vk.q4),
                ("qm", &ref_vk.qm),
                ("qc", &ref_vk.qc),
                ("q_arith", &ref_vk.q_arith),
                ("q_delta_range", &ref_vk.q_delta_range),
                ("q_elliptic", &ref_vk.q_elliptic),
                ("q_memory", &ref_vk.q_memory),
                ("q_lookup", &ref_vk.q_lookup),
                ("q_poseidon2_external", &ref_vk.q_poseidon2_external),
                ("q_poseidon2_internal", &ref_vk.q_poseidon2_internal),
                ("s1", &ref_vk.s1),
                ("s2", &ref_vk.s2),
                ("s3", &ref_vk.s3),
                ("s4", &ref_vk.s4),
                ("t1", &ref_vk.t1),
                ("t2", &ref_vk.t2),
                ("t3", &ref_vk.t3),
                ("t4", &ref_vk.t4),
                ("id1", &ref_vk.id1),
                ("id2", &ref_vk.id2),
                ("id3", &ref_vk.id3),
                ("id4", &ref_vk.id4),
                ("lagrange_first", &ref_vk.lagrange_first),
                ("lagrange_last", &ref_vk.lagrange_last),
                ("q_nnf", &ref_vk.q_nnf),
            ];
            // For each label, find the matching raw point
            let mut take = vec![false; raw_points.len()];
            let mut get = |target: &G1Point| -> Option<G1Point> {
                for (i, rp) in raw_points.iter().enumerate() {
                    if !take[i] && rp.x == target.x && rp.y == target.y { take[i] = true; return Some(rp.clone()); }
                }
                None
            };
            let mut out = Vec::new();
            for &(_, pt) in &ref_list { if let Some(m) = get(pt) { out.push(m); } else { out.push(G1Point{ x: Fq::from(0u64), y: Fq::from(0u64)}); } }
            if out.len() == 28 { mapped = Some((ref_vk, out)); }
        }
    }

    let (ql, qr, qo, q4, qm, qc, q_arith, q_delta_range, q_elliptic, q_memory, q_lookup, q_poseidon2_external, q_poseidon2_internal, s1, s2, s3, s4, t1, t2, t3, t4, id1, id2, id3, id4, lagrange_first, lagrange_last, q_nnf) = if let Some((_ref_vk, out)) = mapped {
        (
            out[0].clone(), out[1].clone(), out[2].clone(), out[3].clone(), out[4].clone(), out[5].clone(),
            out[6].clone(), out[7].clone(), out[8].clone(), out[9].clone(), out[10].clone(), out[11].clone(), out[12].clone(),
            out[13].clone(), out[14].clone(), out[15].clone(), out[16].clone(),
            out[17].clone(), out[18].clone(), out[19].clone(), out[20].clone(),
            out[21].clone(), out[22].clone(), out[23].clone(), out[24].clone(),
            out[25].clone(), out[26].clone(), out[27].clone(),
        )
    } else {
        // Fallback: assume Solidity order
        let mut it = raw_points.into_iter();
        (
            it.next().unwrap(), it.next().unwrap(), it.next().unwrap(), it.next().unwrap(), // ql,qr,qo,q4
            it.next().unwrap(), it.next().unwrap(), // qm,qc
            it.next().unwrap(), it.next().unwrap(), it.next().unwrap(), // q_arith, q_delta_range, q_elliptic
            it.next().unwrap(), // q_memory
            it.next().unwrap(), // q_lookup
            it.next().unwrap(), it.next().unwrap(), // q_poseidon2_external, q_poseidon2_internal
            it.next().unwrap(), it.next().unwrap(), it.next().unwrap(), it.next().unwrap(), // s1..s4
            it.next().unwrap(), it.next().unwrap(), it.next().unwrap(), it.next().unwrap(), // t1..t4
            it.next().unwrap(), it.next().unwrap(), it.next().unwrap(), it.next().unwrap(), // id1..id4
            it.next().unwrap(), it.next().unwrap(), // lagrange_first, lagrange_last
            G1Point { x: Fq::from(0u64), y: Fq::from(0u64) },
        )
    };

    let mut vk = VerificationKey {
        circuit_size: 0,
        log_circuit_size: 0,
        public_inputs_size: 0,
        pub_inputs_offset: 0,
        qm,
        qc,
        ql,
        qr,
        qo,
        q4,
        q_lookup,
        q_arith,
        q_delta_range,
        q_elliptic,
        q_memory,
        q_nnf,
        q_poseidon2_external,
        q_poseidon2_internal,
        s1,
        s2,
        s3,
        s4,
        id1,
        id2,
        id3,
        id4,
        t1,
        t2,
        t3,
        t4,
        lagrange_first,
        lagrange_last,
    };

    // Try to fill header fields from sibling vk_fields.json if present
    if let Ok(txt) = fs::read_to_string(path.with_file_name("vk_fields.json")) {
        if let Ok(vk_fields) = serde_json::from_str::<Vec<String>>(&txt) {
            let parse_u64_hex = |s: &str| -> u64 {
                let x = BigUint::from_str_radix(s.trim_start_matches("0x"), 16).unwrap();
                x.to_u64_digits().get(0).copied().unwrap_or(0)
            };
            if vk_fields.len() >= 1 {
                let h0 = parse_u64_hex(&vk_fields[0]);
                if h0 != 0 && (h0 & (h0 - 1)) == 0 {
                    // power of two -> circuit_size
                    vk.circuit_size = h0;
                    let mut lg = 0u64; let mut n = h0; while n > 1 { n >>= 1; lg += 1; }
                    vk.log_circuit_size = lg;
                } else {
                    // treat as log2(circuit_size)
                    vk.log_circuit_size = h0;
                    vk.circuit_size = 1u64.checked_shl(h0 as u32).unwrap_or(0);
                }
            }
            if vk_fields.len() >= 2 { vk.public_inputs_size = parse_u64_hex(&vk_fields[1]); }
            if vk_fields.len() >= 3 { vk.pub_inputs_offset = parse_u64_hex(&vk_fields[2]); }
        }
    }

    Some(vk)
}

/// Load a proof and public inputs from a byte array.
pub fn load_proof_and_public_inputs(bytes: &[u8]) -> (Vec<Fr>, Vec<u8>) {
    // First 4 bytes = total number of field elements (big-endian)
    let total_fields = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;

    // Proof is always 440 field elements
    const PROOF_NUM_FIELDS: usize = 440;
    assert!(
        total_fields >= PROOF_NUM_FIELDS,
        "total_fields < proof field count"
    );
    let num_inputs = total_fields - PROOF_NUM_FIELDS;

    // Next num_inputs × 32 bytes = public inputs
    let mut public_inputs = Vec::with_capacity(num_inputs);
    let mut cursor = 4; // start right after the 4-byte header
    for _ in 0..num_inputs {
        let mut bytes32 = [0u8; 32];
        bytes32.copy_from_slice(&bytes[cursor..cursor + 32]);
        public_inputs.push(bytes_to_fr(&bytes32));
        cursor += 32;
    }

    // Remaining bytes = proof (must be 440 × 32 bytes)
    let proof_bytes = bytes[cursor..].to_vec();
    assert!(
        proof_bytes.len() == PROOF_NUM_FIELDS * 32,
        "invalid proof length"
    );

    (public_inputs, proof_bytes)
}

// relations.rs
//! Relation evaluation accumulation for UltraHonk.
//!
//! This module accumulates all of the UltraHonk relations (arithmetic, permutation,
//! lookup, range, elliptic, auxiliary, Poseidon external/internal) into a single
//! scalar which is then batched with the alpha challenges.

use crate::field::Fr;
use crate::types::{RelationParameters, Wire};
use std::ops::Neg;

/// Precomputed NEG_HALF = (p - 1)/2 in BN254 scalar field.
fn neg_half() -> Fr {
    Fr::from_str("0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000")
}

/// Internal matrix diagonal values for Poseidon hash
fn internal_matrix_diagonal() -> [Fr; 4] {
    [
        Fr::from_str("0x10dc6e9c006ea38b04b1e03b4bd9490c0d03f98929ca1d7fb56821fd19d3b6e7"),
        Fr::from_str("0x0c28145b6a44df3e0149b3d0a30b3bb599df9756d4dd9b84a86b38cfb45a740b"),
        Fr::from_str("0x00544b8338791518b2c7645a50392798b21f75bb60e3596170067d00141cac15"),
        Fr::from_str("0x222c01175718386f2e2e82eb122789e352e105a3b8fa852613bc534433ee428b"),
    ]
}

/// Helper to index into the wire array.
fn wire(vals: &[Fr], w: Wire) -> Fr {
    vals[w.index()]
}

/// Accumulate the two arithmetic subrelations (indices 0 and 1).
fn accumulate_arithmetic(vals: &[Fr], out: &mut [Fr], d: Fr) {
    // Subrelation 0: quadratic gate combination
    {
        let q = wire(vals, Wire::QArith);
        let mut acc = (q - Fr::from_u64(3))
            * wire(vals, Wire::Qm)
            * wire(vals, Wire::Wr)
            * wire(vals, Wire::Wl)
            * neg_half();
        acc = acc
            + wire(vals, Wire::Ql) * wire(vals, Wire::Wl)
            + wire(vals, Wire::Qr) * wire(vals, Wire::Wr)
            + wire(vals, Wire::Qo) * wire(vals, Wire::Wo)
            + wire(vals, Wire::Q4) * wire(vals, Wire::W4)
            + wire(vals, Wire::Qc);
        acc = (acc + (q - Fr::one()) * wire(vals, Wire::W4Shift)) * q * d;
        out[0] = acc;
    }
    // Subrelation 1: indicator for q_m
    {
        let q = wire(vals, Wire::QArith);
        let mut acc = wire(vals, Wire::Wl)
            + wire(vals, Wire::W4)
            - wire(vals, Wire::WlShift)
            + wire(vals, Wire::Qm);
        acc = acc
            * (q - Fr::from_u64(2))
            * (q - Fr::from_u64(1))
            * q
            * d;
        out[1] = acc;
    }
}

/// Accumulate the two permutation subrelations (indices 2 and 3).
fn accumulate_permutation(vals: &[Fr], rp: &RelationParameters, out: &mut [Fr], d: Fr) {
    let mut num = wire(vals, Wire::Wl) + wire(vals, Wire::Id1) * rp.beta + rp.gamma;
    num = num
        * (wire(vals, Wire::Wr) + wire(vals, Wire::Id2) * rp.beta + rp.gamma)
        * (wire(vals, Wire::Wo) + wire(vals, Wire::Id3) * rp.beta + rp.gamma)
        * (wire(vals, Wire::W4) + wire(vals, Wire::Id4) * rp.beta + rp.gamma);

    let mut den = wire(vals, Wire::Wl) + wire(vals, Wire::Sigma1) * rp.beta + rp.gamma;
    den = den
        * (wire(vals, Wire::Wr) + wire(vals, Wire::Sigma2) * rp.beta + rp.gamma)
        * (wire(vals, Wire::Wo) + wire(vals, Wire::Sigma3) * rp.beta + rp.gamma)
        * (wire(vals, Wire::W4) + wire(vals, Wire::Sigma4) * rp.beta + rp.gamma);

    out[2] = (wire(vals, Wire::ZPerm) + wire(vals, Wire::LagrangeFirst)) * num
        - (wire(vals, Wire::ZPermShift) + wire(vals, Wire::LagrangeLast) * rp.public_inputs_delta)
            * den;
    out[2] = out[2] * d;
    out[3] = wire(vals, Wire::LagrangeLast) * wire(vals, Wire::ZPermShift) * d;
}

/// Accumulate the two lookup log‐derivative subrelations (indices 4 and 5).
fn accumulate_lookup(vals: &[Fr], rp: &RelationParameters, out: &mut [Fr], d: Fr) {
    let write_term = wire(vals, Wire::Table1)
        + rp.gamma
        + wire(vals, Wire::Table2) * rp.eta
        + wire(vals, Wire::Table3) * rp.eta_two
        + wire(vals, Wire::Table4) * rp.eta_three;

    let derived_entry_2 =
        wire(vals, Wire::Wr) + wire(vals, Wire::Qm) * wire(vals, Wire::WrShift);
    let derived_entry_3 =
        wire(vals, Wire::Wo) + wire(vals, Wire::Qc) * wire(vals, Wire::WoShift);
    
    let read_term = wire(vals, Wire::Wl) + rp.gamma
        + wire(vals, Wire::Qr) * wire(vals, Wire::WlShift)
        + derived_entry_2 * rp.eta
        + derived_entry_3 * rp.eta_two
        + wire(vals, Wire::Qo) * rp.eta_three;

    let inv = wire(vals, Wire::LookupInverses);
    let inv_exists = wire(vals, Wire::LookupReadTags)
        + wire(vals, Wire::QLookup)
        - wire(vals, Wire::LookupReadTags) * wire(vals, Wire::QLookup);

    out[4] = (read_term * write_term * inv - inv_exists) * d;
    out[5] = wire(vals, Wire::QLookup) * (write_term * inv)
         - wire(vals, Wire::LookupReadCounts) * (read_term * inv);
}

/// Accumulate the four range‐check subrelations (indices 6..9).
fn accumulate_range(vals: &[Fr], out: &mut [Fr], d: Fr) {
    let deltas = [
        wire(vals, Wire::Wr) - wire(vals, Wire::Wl),
        wire(vals, Wire::Wo) - wire(vals, Wire::Wr),
        wire(vals, Wire::W4) - wire(vals, Wire::Wo),
        wire(vals, Wire::WlShift) - wire(vals, Wire::W4),
    ];
    let negs = [Fr::from_u64(1).neg(), Fr::from_u64(2).neg(), Fr::from_u64(3).neg()];
    for i in 0..4 {
        let mut acc = deltas[i];
        for &n in &negs {
            acc = acc * (deltas[i] + n);
        }
        out[6 + i] = acc * wire(vals, Wire::QRange) * d;
    }
}

/// Accumulate elliptic‐curve subrelations (indices 10..11).
fn accumulate_elliptic(vals: &[Fr], out: &mut [Fr], d: Fr) {
    let x1 = wire(vals, Wire::Wr);
    let y1 = wire(vals, Wire::Wo);
    let x2 = wire(vals, Wire::WlShift);
    let y2 = wire(vals, Wire::W4Shift);
    let x3 = wire(vals, Wire::WrShift);
    let y3 = wire(vals, Wire::WoShift);

    let q_sign = wire(vals, Wire::Ql);
    let q_double = wire(vals, Wire::Qm);
    let q_gate = wire(vals, Wire::QElliptic);

    let delta_x = x2 - x1;
    let y1_sq = y1 * y1;

    let x_add_id = {
        let y2_sq = y2 * y2;
        let y1y2 = y1 * y2 * q_sign;
        (x3 + x2 + x1) * delta_x * delta_x - y2_sq - y1_sq + y1y2 + y1y2
    };
    let y_add_id = {
        let y_diff = y2 * q_sign - y1;
        (y1 + y3) * delta_x + (x3 - x1) * y_diff
    };

    const B_NEG: u64 = 17;
    let b_neg = Fr::from_u64(B_NEG);

    let x_double_id = {
        let x_pow_4 = (y1_sq + b_neg) * x1;
        let y1_sqr_mul_4 = y1_sq + y1_sq + y1_sq + y1_sq;
        let x_pow_4_mul_9 = x_pow_4 * Fr::from_u64(9);
        (x3 + x1 + x1) * y1_sqr_mul_4 - x_pow_4_mul_9
    };
    let y_double_id = {
        let x1_sqr_mul_3 = (x1 + x1 + x1) * x1;
        x1_sqr_mul_3 * (x1 - x3) - (y1 + y1) * (y1 + y3)
    };

    let add_factor = (Fr::one() - q_double) * q_gate * d;
    let double_factor = q_double * q_gate * d;

    out[10] = x_add_id * add_factor + x_double_id * double_factor;
    out[11] = y_add_id * add_factor + y_double_id * double_factor;
}

/// Accumulate auxiliary subrelations (indices 12..17).
fn accumulate_aux(vals: &[Fr], rp: &RelationParameters, out: &mut [Fr], d: Fr) {
    fn limb_size() -> Fr {
        Fr::from_str("0x100000000000000000")
    }
    fn sublimb_shift() -> Fr {
        Fr::from_u64(1 << 14)
    }

    let mut limb_subproduct = wire(vals, Wire::Wl) * wire(vals, Wire::WrShift)
        + wire(vals, Wire::WlShift) * wire(vals, Wire::Wr);

    let mut gate2 = wire(vals, Wire::Wl) * wire(vals, Wire::W4)
        + wire(vals, Wire::Wr) * wire(vals, Wire::Wo)
        - wire(vals, Wire::WoShift);
    gate2 = gate2 * limb_size() - wire(vals, Wire::W4Shift) + limb_subproduct;
    gate2 = gate2 * wire(vals, Wire::Q4);

    limb_subproduct = limb_subproduct * limb_size()
        + wire(vals, Wire::WlShift) * wire(vals, Wire::WrShift);

    let gate1 = (limb_subproduct - (wire(vals, Wire::Wo) + wire(vals, Wire::W4)))
        * wire(vals, Wire::Qo);

    let gate3 = (limb_subproduct + wire(vals, Wire::W4)
        - (wire(vals, Wire::WoShift) + wire(vals, Wire::W4Shift)))
        * wire(vals, Wire::Qm);

    let non_native_field_identity = (gate1 + gate2 + gate3) * wire(vals, Wire::Qr);

    let mut limb_acc_1 = wire(vals, Wire::WrShift) * sublimb_shift() + wire(vals, Wire::WlShift);
    limb_acc_1 = limb_acc_1 * sublimb_shift() + wire(vals, Wire::Wo);
    limb_acc_1 = limb_acc_1 * sublimb_shift() + wire(vals, Wire::Wr);
    limb_acc_1 = limb_acc_1 * sublimb_shift() + wire(vals, Wire::Wl);
    limb_acc_1 = (limb_acc_1 - wire(vals, Wire::W4)) * wire(vals, Wire::Q4);

    let mut limb_acc_2 = wire(vals, Wire::WoShift) * sublimb_shift() + wire(vals, Wire::WrShift);
    limb_acc_2 = limb_acc_2 * sublimb_shift() + wire(vals, Wire::WlShift);
    limb_acc_2 = limb_acc_2 * sublimb_shift() + wire(vals, Wire::W4);
    limb_acc_2 = limb_acc_2 * sublimb_shift() + wire(vals, Wire::Wo);
    limb_acc_2 = (limb_acc_2 - wire(vals, Wire::W4Shift)) * wire(vals, Wire::Qm);

    let limb_acc_identity = (limb_acc_1 + limb_acc_2) * wire(vals, Wire::Qo);

    let mut mr = wire(vals, Wire::Wo) * rp.eta_three
        + wire(vals, Wire::Wr) * rp.eta_two
        + wire(vals, Wire::Wl) * rp.eta
        + wire(vals, Wire::Qc);
    let partial = mr;
    mr = mr - wire(vals, Wire::W4);

    let idx_delta = wire(vals, Wire::WlShift) - wire(vals, Wire::Wl);
    let rec_delta = wire(vals, Wire::W4Shift) - wire(vals, Wire::W4);

    let idx_inc = idx_delta * idx_delta - idx_delta;
    let adj_match  = (Fr::one() - idx_delta) * rec_delta;

    out[13] = adj_match * wire(vals, Wire::Ql) * wire(vals, Wire::Qr) * wire(vals, Wire::QAux) * d;
    out[14] = idx_inc * wire(vals, Wire::Ql) * wire(vals, Wire::Qr) * wire(vals, Wire::QAux) * d;

    let access_type = wire(vals, Wire::W4) - partial;
    let access_check = access_type * access_type - access_type;

    let mut next_gate = wire(vals, Wire::WoShift) * rp.eta_three
        + wire(vals, Wire::WrShift) * rp.eta_two
        + wire(vals, Wire::WlShift) * rp.eta;
    next_gate = wire(vals, Wire::W4Shift) - next_gate;

    let val_delta = wire(vals, Wire::WoShift) - wire(vals, Wire::Wo);
    let adj_match2 = (Fr::one() - idx_delta)
        * val_delta
        * (Fr::one() - next_gate);

    out[15] = adj_match2 * wire(vals, Wire::QArith) * wire(vals, Wire::QAux) * d;
    out[16] = idx_inc * wire(vals, Wire::QArith) * wire(vals, Wire::QAux) * d;
    out[17] = (next_gate * next_gate - next_gate) * wire(vals, Wire::QArith) * wire(vals, Wire::QAux) * d;

    let rom_consistency = mr * wire(vals, Wire::Ql) * wire(vals, Wire::Qr);
    let ram_timestamp = (Fr::one() - idx_delta)
        * (wire(vals, Wire::WrShift) - wire(vals, Wire::Wr))
        - wire(vals, Wire::Wo);
    let ram_consistency = access_check * wire(vals, Wire::QArith);

    let memory_identity = rom_consistency
        + ram_timestamp * wire(vals, Wire::Q4) * wire(vals, Wire::Ql)
        + mr * wire(vals, Wire::Qm) * wire(vals, Wire::Ql)
        + ram_consistency;

    out[12] = (memory_identity + non_native_field_identity + limb_acc_identity)
        * wire(vals, Wire::QAux)
        * d;
}

/// Accumulate Poseidon external (18..21) and internal (22..25) subrelations.
fn accumulate_poseidon(vals: &[Fr], out: &mut [Fr], d: Fr) {
    let s1 = wire(vals, Wire::Wl) + wire(vals, Wire::Ql);

    let u1 = s1.pow(5);
    let u2 = wire(vals, Wire::Wr);
    let u3 = wire(vals, Wire::Wo);
    let u4 = wire(vals, Wire::W4);

    let t0 = u1 + u2;
    let t1 = u3 + u4;
    let t2 = u2 + u2 + t1;
    let t3 = u4 + u4 + t0;

    let v4 = t1 + t1 + t1 + t1 + t3;
    let v2 = t0 + t0 + t0 + t0 + t2;
    let v1 = t3 + v2;
    let v3 = t2 + v4;

    let qpos = wire(vals, Wire::QPoseidon2External);
    out[18] = (v1 - wire(vals, Wire::WlShift)) * qpos * d;
    out[19] = (v2 - wire(vals, Wire::WrShift)) * qpos * d;
    out[20] = (v3 - wire(vals, Wire::WoShift)) * qpos * d;
    out[21] = (v4 - wire(vals, Wire::W4Shift)) * qpos * d;

    let ipos = wire(vals, Wire::QPoseidon2Internal);
    let u_sum = u1 + u2 + u3 + u4;
    let diag = internal_matrix_diagonal();

    let w1 = u1 * diag[0] + u_sum;
    let w2 = u2 * diag[1] + u_sum;
    let w3 = u3 * diag[2] + u_sum;
    let w4 = u4 * diag[3] + u_sum;

    out[22] = (w1 - wire(vals, Wire::WlShift)) * ipos * d;
    out[23] = (w2 - wire(vals, Wire::WrShift)) * ipos * d;
    out[24] = (w3 - wire(vals, Wire::WoShift)) * ipos * d;
    out[25] = (w4 - wire(vals, Wire::W4Shift)) * ipos * d;
}

/// Batch all NUM_SUBRELATIONS = 26 subrelations with the alpha challenges.
fn batch_subrelations(evals: &[Fr], alphas: &[Fr]) -> Fr {
    let mut acc = evals[0];
    for (i, alpha) in alphas.iter().enumerate() {
        acc = acc + evals[i + 1] * *alpha;
    }
    acc
}

/// Main entrypoint: accumulate all subrelations and batch with alphas.
pub fn accumulate_relation_evaluations(
    vals: &[Fr],
    rp: &RelationParameters,
    alphas: &[Fr],
    pow_partial: Fr,
) -> Fr {
    const NUM_SUBRELATIONS: usize = 26;
    let mut out = vec![Fr::zero(); NUM_SUBRELATIONS];
    let d = pow_partial;

    accumulate_arithmetic(vals, &mut out, d);
    accumulate_permutation(vals, rp, &mut out, d);
    accumulate_lookup(vals, rp, &mut out, d);
    accumulate_range(vals, &mut out, d);
    accumulate_elliptic(vals, &mut out, d);
    accumulate_aux(vals, rp, &mut out, d);
    accumulate_poseidon(vals, &mut out, d);

    batch_subrelations(&out, alphas)
}

pub fn dump_subrelations(
    vals: &[Fr],
    rp: &RelationParameters,
    alphas: &[Fr],
    pow_partial: Fr,
) -> Fr {
    const NUM: usize = 26;
    let mut out = vec![Fr::zero(); NUM];
    let d = pow_partial;

    accumulate_arithmetic(vals, &mut out, d);
    accumulate_permutation(vals, rp, &mut out, d);
    accumulate_lookup(vals, rp, &mut out, d);
    accumulate_range(vals, &mut out, d);
    accumulate_elliptic(vals, &mut out, d);
    accumulate_aux(vals, rp, &mut out, d);
    accumulate_poseidon(vals, &mut out, d);

    println!("===== SUBRELATIONS (Rust) =====");
    for (i, v) in out.iter().enumerate() {
        println!("rel[{i:02}] = 0x{}", hex::encode(v.to_bytes()));
    }
    println!("===============================");

    batch_subrelations(&out, alphas)
}

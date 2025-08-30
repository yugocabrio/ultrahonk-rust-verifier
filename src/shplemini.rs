//! Shplemini batch-opening verifier for BN254

#[cfg(feature = "trace")]
use crate::debug::{dbg_fr, dbg_vec, dump_pairs};
use crate::field::Fr;
use crate::trace;
use crate::types::{G1Point, Proof, Transcript, VerificationKey, CONST_PROOF_SIZE_LOG_N};
#[cfg(not(feature = "std"))]
use alloc::format;
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, CurveGroup, PrimeGroup};
#[cfg(feature = "trace")]
use ark_ff::BigInteger;
use ark_ff::{One, PrimeField, Zero};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

pub const NUMBER_UNSHIFTED: usize = 35; // = 40 – 5
pub const NUMBER_SHIFTED: usize = 5; // Final 5 are shifted
const NUMBER_OF_ENTITIES: usize = NUMBER_UNSHIFTED + NUMBER_SHIFTED; // 40

#[inline(always)]
fn affine_checked(pt: &G1Point) -> Result<G1Affine, String> {
    let aff = G1Affine::new_unchecked(pt.x, pt.y);
    if aff.is_on_curve() && aff.is_in_correct_subgroup_assuming_on_curve() {
        Ok(aff)
    } else {
        Err("invalid G1 point (not on curve)".into())
    }
}

#[inline(always)]
fn negate(pt: &G1Point) -> G1Point {
    G1Point { x: pt.x, y: -pt.y }
}

/// ∑ sᵢ·Cᵢ
fn batch_mul(coms: &[G1Point], scalars: &[Fr]) -> Result<G1Affine, String> {
    if coms.len() != scalars.len() {
        return Err("commitments / scalars length mismatch".into());
    }
    let mut acc = G1Projective::zero();
    trace!("Initial acc: {:?}", acc);

    for (i, (c, s)) in coms.iter().zip(scalars.iter()).enumerate() {
        let aff = G1Affine::new_unchecked(c.x, c.y);
        if !aff.is_on_curve() || !aff.is_in_correct_subgroup_assuming_on_curve() {
            trace!(
                "Invalid G1 at x=0x{} y=0x{}",
                hex::encode(c.x.into_bigint().to_bytes_be()),
                hex::encode(c.y.into_bigint().to_bytes_be())
            );
            return Err("invalid G1 point".into());
        }

        trace!("Iteration {}: Processing point", i);
        trace!(
            "  Point (x): 0x{}",
            hex::encode(c.x.into_bigint().to_bytes_be())
        );
        trace!(
            "  Point (y): 0x{}",
            hex::encode(c.y.into_bigint().to_bytes_be())
        );
        trace!("  Scalar     : 0x{}", hex::encode(s.to_bytes()));

        // Always process, even for zero scalar, to mirror Solidity's batchMul
        acc += G1Projective::from(aff).mul_bigint(s.0.into_bigint());
        let acc_aff = acc.into_affine();
        trace!("  Accumulated result:");
        trace!(
            "    x: 0x{}",
            hex::encode(acc_aff.x.into_bigint().to_bytes_be())
        );
        trace!(
            "    y: 0x{}",
            hex::encode(acc_aff.y.into_bigint().to_bytes_be())
        );
        acc = G1Projective::from(acc_aff);
        trace!();
    }

    let final_aff = acc.into_affine();
    trace!("Final result:");
    trace!(
        "  x: 0x{}",
        hex::encode(final_aff.x.into_bigint().to_bytes_be())
    );
    trace!(
        "  y: 0x{}",
        hex::encode(final_aff.y.into_bigint().to_bytes_be())
    );
    Ok(final_aff)
}

/// pairing check
/// This function checks the pairing condition for the given G1 points.
fn pairing_check(p0: &G1Affine, p1: &G1Affine) -> bool {
    // fixed RHS G2 (inputValues[2-5])
    let rhs_g2 = {
        let x = Fq2::new(
            Fq::from_le_bytes_mod_order(&[
                0xed, 0xf6, 0x92, 0xd9, 0x5c, 0xbd, 0xde, 0x46, 0xdd, 0xda, 0x5e, 0xf7, 0xd4, 0x22,
                0x43, 0x67, 0x79, 0x44, 0x5c, 0x5e, 0x66, 0x00, 0x6a, 0x42, 0x76, 0x1e, 0x1f, 0x12,
                0xef, 0xde, 0x00, 0x18,
            ]),
            Fq::from_le_bytes_mod_order(&[
                0xc2, 0x12, 0xf3, 0xae, 0xb7, 0x85, 0xe4, 0x97, 0x12, 0xe7, 0xa9, 0x35, 0x33, 0x49,
                0xaa, 0xf1, 0x25, 0x5d, 0xfb, 0x31, 0xb7, 0xbf, 0x60, 0x72, 0x3a, 0x48, 0x0d, 0x92,
                0x93, 0x93, 0x8e, 0x19,
            ]),
        );
        let y = Fq2::new(
            Fq::from_le_bytes_mod_order(&[
                0xaa, 0x7d, 0xfa, 0x66, 0x01, 0xcc, 0xe6, 0x4c, 0x7b, 0xd3, 0x43, 0x0c, 0x69, 0xe7,
                0xd1, 0xe3, 0x8f, 0x40, 0xcb, 0x8d, 0x80, 0x71, 0xab, 0x4a, 0xeb, 0x6d, 0x8c, 0xdb,
                0xa5, 0x5e, 0xc8, 0x12,
            ]),
            Fq::from_le_bytes_mod_order(&[
                0x5b, 0x97, 0x22, 0xd1, 0xdc, 0xda, 0xac, 0x55, 0xf3, 0x8e, 0xb3, 0x70, 0x33, 0x31,
                0x4b, 0xbc, 0x95, 0x33, 0x0c, 0x69, 0xad, 0x99, 0x9e, 0xec, 0x75, 0xf0, 0x5f, 0x58,
                0xd0, 0x89, 0x06, 0x09,
            ]),
        );
        G2Affine::new_unchecked(x, y)
    };
    // fixed LHS G2 (VK)
    let lhs_g2 = {
        let x = Fq2::new(
            Fq::from_le_bytes_mod_order(&[
                0xb0, 0x83, 0x88, 0x93, 0xec, 0x1f, 0x23, 0x7e, 0x8b, 0x07, 0x32, 0x3b, 0x07, 0x44,
                0x59, 0x9f, 0x4e, 0x97, 0xb5, 0x98, 0xb3, 0xb5, 0x89, 0xbc, 0xc2, 0xbc, 0x37, 0xb8,
                0xd5, 0xc4, 0x18, 0x01,
            ]),
            Fq::from_le_bytes_mod_order(&[
                0xc1, 0x83, 0x93, 0xc0, 0xfa, 0x30, 0xfe, 0x4e, 0x8b, 0x03, 0x8e, 0x35, 0x7a, 0xd8,
                0x51, 0xea, 0xe8, 0xde, 0x91, 0x07, 0x58, 0x4e, 0xff, 0xe7, 0xc7, 0xf1, 0xf6, 0x51,
                0xb2, 0x01, 0x0e, 0x26,
            ]),
        );
        let y = Fq2::new(
            Fq::from_le_bytes_mod_order(&[
                0x55, 0x5e, 0xcc, 0xda, 0xd4, 0x87, 0x4a, 0x85, 0xa2, 0xce, 0xe6, 0x96, 0x3f, 0xdd,
                0xe6, 0x11, 0x5e, 0x61, 0xe5, 0x14, 0x42, 0x5b, 0x47, 0x56, 0x2a, 0x63, 0xc0, 0xc0,
                0xa3, 0xbd, 0xfe, 0x22,
            ]),
            Fq::from_le_bytes_mod_order(&[
                0xe4, 0x5f, 0x6a, 0xda, 0x80, 0x3c, 0x41, 0xee, 0xa4, 0x9b, 0xf9, 0x41, 0x46, 0xa0,
                0xf2, 0x9c, 0x85, 0x72, 0x9a, 0xbb, 0xc1, 0x56, 0x51, 0xd2, 0xe3, 0x0f, 0x11, 0xf7,
                0x69, 0x63, 0xfc, 0x04,
            ]),
        );
        G2Affine::new_unchecked(x, y)
    };

    let e1 = Bn254::pairing(*p0, rhs_g2);
    let e2 = Bn254::pairing(*p1, lhs_g2);
    e1.0 * e2.0 == <Bn254 as Pairing>::TargetField::one()
}

/// Shplemini verification
pub fn verify_shplemini(
    proof: &Proof,
    vk: &VerificationKey,
    tx: &Transcript,
) -> Result<(), String> {
    // 1) r^{2^i}
    let log_n = vk.log_circuit_size as usize;
    let mut r_pows = Vec::with_capacity(log_n);
    r_pows.push(tx.gemini_r);
    for i in 1..log_n {
        r_pows.push(r_pows[i - 1] * r_pows[i - 1]);
    }
    #[cfg(feature = "trace")]
    {
        trace!("===== Step-1 parameters =====");
        dbg_fr("gemini_r", &tx.gemini_r);
        dbg_vec("r_pow", &r_pows);
        trace!("==============================");
    }

    // 2) allocate arrays
    // Match Solidity sizing: NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 2
    // Layout:
    //   [0]                 = shplonk_Q
    //   [1..=40]            = VK + proof entities (NUMBER_OF_ENTITIES)
    //   [41..=67]           = gemini_fold_comms (CONST_PROOF_SIZE_LOG_N - 1 = 27)
    //   [68]                = generator (1,2) with const_acc scalar
    //   [69]                = kzg_quotient with scalar z
    let total = 1 + NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 1;
    trace!("total = {}", total);
    let mut scalars = vec![Fr::zero(); total];
    let mut coms = vec![
        G1Point {
            x: Fq::zero(),
            y: Fq::zero()
        };
        total
    ];

    // 3) compute shplonk weights
    let pos0 = (tx.shplonk_z - r_pows[0]).inverse();
    let neg0 = (tx.shplonk_z + r_pows[0]).inverse();
    let unshifted = pos0 + tx.shplonk_nu * neg0;
    let shifted = tx.gemini_r.inverse() * (pos0 - tx.shplonk_nu * neg0);
    #[cfg(feature = "trace")]
    {
        dbg_fr("pos0", &pos0);
        dbg_fr("neg0", &neg0);
        dbg_fr("unshifted", &unshifted);
        dbg_fr("shifted", &shifted);
    }

    // 4) shplonk_Q
    scalars[0] = Fr::one();
    coms[0] = proof.shplonk_q.clone();

    // 5) weight sumcheck evals
    let mut rho_pow = Fr::one();
    let mut eval_acc = Fr::zero();
    for (idx, eval) in proof
        .sumcheck_evaluations
        .iter()
        .take(NUMBER_OF_ENTITIES)
        .enumerate()
    {
        let scalar = if idx < NUMBER_UNSHIFTED {
            -unshifted
        } else {
            -shifted
        } * rho_pow;
        scalars[1 + idx] = scalar;
        eval_acc = eval_acc + (*eval * rho_pow);
        rho_pow = rho_pow * tx.rho;
    }
    #[cfg(feature = "trace")]
    {
        dbg_fr("eval_acc_end", &eval_acc);
    }

    // 6) load VK & proof
    {
        let mut j = 1;
        macro_rules! push {
            ($f:ident) => {{
                coms[j] = vk.$f.clone();
                j += 1;
            }};
        }
        push!(qm);
        push!(qc);
        push!(ql);
        push!(qr);
        push!(qo);
        push!(q4);
        // Match Solidity VK commitment order strictly
        // 7..13: qLookup, qArith, qDeltaRange, qElliptic, qAux (q_memory), qPoseidon2External, qPoseidon2Internal
        push!(q_lookup);
        push!(q_arith);
        push!(q_delta_range);
        push!(q_elliptic);
        push!(q_memory); // qAux in Solidity
        push!(q_poseidon2_external);
        push!(q_poseidon2_internal);
        push!(s1);
        push!(s2);
        push!(s3);
        push!(s4);
        push!(id1);
        push!(id2);
        push!(id3);
        push!(id4);
        push!(t1);
        push!(t2);
        push!(t3);
        push!(t4);
        push!(lagrange_first);
        push!(lagrange_last);

        coms[j] = proof.w1.clone();
        j += 1;
        coms[j] = proof.w2.clone();
        j += 1;
        coms[j] = proof.w3.clone();
        j += 1;
        coms[j] = proof.w4.clone();
        j += 1;
        coms[j] = proof.z_perm.clone();
        j += 1;
        coms[j] = proof.lookup_inverses.clone();
        j += 1;
        coms[j] = proof.lookup_read_counts.clone();
        j += 1;
        coms[j] = proof.lookup_read_tags.clone();
        j += 1;

        coms[j] = proof.w1.clone();
        j += 1;
        coms[j] = proof.w2.clone();
        j += 1;
        coms[j] = proof.w3.clone();
        j += 1;
        coms[j] = proof.w4.clone();
        j += 1;
        coms[j] = proof.z_perm.clone();
        j += 1;
        let _ = j; // silence "assigned but never read" in non-trace builds
    }

    // 7) folding rounds
    let mut fold_pos = vec![Fr::zero(); log_n];
    let mut cur = eval_acc;
    for j in (1..=log_n).rev() {
        let r2 = r_pows[j - 1];
        let u = tx.sumcheck_u_challenges[j - 1];
        let num = r2 * cur * Fr::from_u64(2)
            - proof.gemini_a_evaluations[j - 1] * (r2 * (Fr::one() - u) - u);
        let den = r2 * (Fr::one() - u) + u;
        cur = num * den.inverse();
        fold_pos[j - 1] = cur;
    }
    #[cfg(feature = "trace")]
    {
        dbg_fr("fold_pos_end", &fold_pos[0]);
    }

    // 8) accumulate constant term
    let mut const_acc = fold_pos[0] * pos0 + proof.gemini_a_evaluations[0] * tx.shplonk_nu * neg0;
    let mut v_pow = tx.shplonk_nu * tx.shplonk_nu;
    #[cfg(feature = "trace")]
    {
        dbg_fr("const_acc_final", &const_acc);
    }

    // 9) further folding + commit
    // Base index where fold commitments start
    let base = 1 + NUMBER_OF_ENTITIES;
    trace!("base = {}", base);
    for j in 1..log_n {
        #[cfg(feature = "trace")]
        {
            trace!("── fold round {} ──────────────", j);
            dbg_fr("v_pow (before)", &v_pow);
        }

        let pos_inv = (tx.shplonk_z - r_pows[j]).inverse();
        let neg_inv = (tx.shplonk_z + r_pows[j]).inverse();
        let sp = v_pow * pos_inv;
        let sn = v_pow * tx.shplonk_nu * neg_inv;

        #[cfg(feature = "trace")]
        {
            dbg_fr("pos_inv", &pos_inv);
            dbg_fr("neg_inv", &neg_inv);
            dbg_fr("scPos", &sp);
            dbg_fr("scNeg", &sn);
            dbg_fr("fold_pos[j]", &fold_pos[j]);
            dbg_fr("A_eval", &proof.gemini_a_evaluations[j]);
        }

        scalars[base + j - 1] = -(sp + sn);
        const_acc = const_acc + proof.gemini_a_evaluations[j] * sn + fold_pos[j] * sp;

        v_pow = v_pow * tx.shplonk_nu * tx.shplonk_nu;

        #[cfg(feature = "trace")]
        {
            dbg_fr("const_acc", &const_acc);
            dbg_fr("v_pow (after)", &v_pow);
        }

        coms[base + j - 1] = proof.gemini_fold_comms[j - 1].clone();
    }

    // Fill remaining (dummy) fold commitments so MSM layout matches Solidity (total 27 entries)
    for i in (log_n - 1)..(CONST_PROOF_SIZE_LOG_N - 1) {
        coms[base + i] = proof.gemini_fold_comms[i].clone();
    }

    // 10) add generator
    // Generator goes right after all fold commitments (27 entries)
    let one_idx = base + (CONST_PROOF_SIZE_LOG_N - 1);
    trace!("one_idx = {}", one_idx);
    let gen = G1Projective::generator().into_affine();
    coms[one_idx] = G1Point { x: gen.x, y: gen.y };
    scalars[one_idx] = const_acc;

    // 11) add quotient
    let q_idx = one_idx + 1;
    trace!("q_idx = {}", q_idx);
    coms[q_idx] = proof.kzg_quotient.clone();
    scalars[q_idx] = tx.shplonk_z;

    // 12) pre-MSM debug
    #[cfg(feature = "trace")]
    {
        trace!("===== Shplonk pre-MSM =====");
        trace!("scalars.len() = {}", scalars.len());
        trace!("coms.len()    = {}", coms.len());
        let base_shift = 1 + NUMBER_UNSHIFTED;
        for k in 0..NUMBER_SHIFTED {
            dbg_fr(&format!("scalar_shifted[{}]", k), &scalars[base_shift + k]);
        }
        trace!("============================");
    }

    // 13) dump all pairs (range + full) for cross-checking with Solidity (trace-only)
    #[cfg(feature = "trace")]
    {
        use crate::debug::dump_pairs_range;
        // sanity-check points are on-curve to locate any invalid index early
        for (i, c) in coms.iter().enumerate() {
            let aff = G1Affine::new_unchecked(c.x, c.y);
            if !aff.is_on_curve() || !aff.is_in_correct_subgroup_assuming_on_curve() {
                trace!(
                    "Precheck: invalid G1 at coms[{}] x=0x{} y=0x{}",
                    i,
                    hex::encode(c.x.into_bigint().to_bytes_be()),
                    hex::encode(c.y.into_bigint().to_bytes_be())
                );
            }
        }
        dump_pairs_range(&coms, &scalars, 0, 15);
        dump_pairs(&coms, &scalars, usize::MAX);
    }

    // 14) MSM + pairing
    let p0 = batch_mul(&coms, &scalars)?;
    let p1 = affine_checked(&negate(&proof.kzg_quotient))?;
    #[cfg(feature = "trace")]
    {
        trace!("===== PAIRING-DEBUG =====");
        dbg_fr("scalar[z]", &scalars[q_idx]);
        trace!("P0.x = 0x{}", hex::encode(p0.x.into_bigint().to_bytes_be()));
        trace!("P0.y = 0x{}", hex::encode(p0.y.into_bigint().to_bytes_be()));
        trace!("P1.x = 0x{}", hex::encode(p1.x.into_bigint().to_bytes_be()));
        trace!("P1.y = 0x{}", hex::encode(p1.y.into_bigint().to_bytes_be()));
        trace!("=========================");
    }

    if pairing_check(&p0, &p1) {
        Ok(())
    } else {
        Err("Shplonk pairing check failed".into())
    }
}

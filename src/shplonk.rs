//! Shplonk batch-opening verifier for BN254
use crate::field::Fr;
use crate::types::{G1Point, Proof, Transcript, VerificationKey};
use crate::debug::{dbg_fr, dbg_vec};
use ark_bn254::{Bn254, G1Affine, G1Projective, G2Affine, G2Projective, Fq, Fq2};
use ark_ec::{pairing::Pairing, CurveGroup, PrimeGroup};
use ark_ff::ark_ff_macros::to_sign_and_limbs;
use ark_ff::{Field, One, Zero, PrimeField, BigInteger256};

/// # 定数
pub const NUMBER_UNSHIFTED: usize = 35; // = 40 – 5
pub const NUMBER_SHIFTED: usize   = 5;  // 後半 5 個

/*──────────────────────── helpers ────────────────────────*/

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

#[inline(always)]
fn is_dummy(pt: &G1Point) -> bool {
    pt.x.is_zero() && pt.y.is_zero()
}

/// ∑ sᵢ·Cᵢ
fn batch_mul(coms: &[G1Point], scalars: &[Fr]) -> Result<G1Affine, String> {
    if coms.len() != scalars.len() {
        return Err("commitments / scalars length mismatch".into());
    }
    let mut acc = G1Projective::zero();
    for (c, s) in coms.iter().zip(scalars.iter()) {
        if s.is_zero() || is_dummy(c) { continue; }
        let aff = G1Affine::new_unchecked(c.x, c.y);
        if !aff.is_on_curve() || !aff.is_in_correct_subgroup_assuming_on_curve() {
            return Err("invalid G1 point (not on curve)".into());
        }
        acc += G1Projective::from(aff).mul_bigint(s.0.into_bigint());
    }
    Ok(acc.into_affine())
}

/*──────────────── pairing 定数 ───────────────*/

fn pairing_check(p0: &G1Affine, p1: &G1Affine) -> bool {
    let g2_gen = G2Projective::generator().into_affine();

    // 固定 vk_G2（TS 側と一致）
    let vk_g2 = {
        let x = Fq2::new(
            Fq::from_bigint(BigInteger256::new([
                0x4efe_30fa_c093_83c1,
                0xea51_d87a_358e_038b,
                0xe7ff_4e58_0791_dee8,
                0x260e_01b2_51f6_f1c7,
            ])).unwrap(),
            Fq::from_bigint(BigInteger256::new([
                0x46de_bd5c_d992_f6ed,
                0x6743_22d4_f75e_dadd,
                0x426a_0066_5e5c_4479,
                0x1800_deef_121f_1e76,
            ])).unwrap(),
        );
        let y = Fq2::new(
            Fq::from_bigint(BigInteger256::new([
                0x55ac_dadc_d122_975b,
                0xbc4b_3133_70b3_8ef3,
                0xec9e_99ad_690c_3395,
                0x0906_89d0_585f_f075,
            ])).unwrap(),
            Fq::from_bigint(BigInteger256::new([
                0x4ce6_cc01_66fa_7daa,
                0xe3d1_e769_0c43_d37b,
                0x4aab_7180_8dcb_408f,
                0x12c8_5ea5_db8c_6deb,
            ])).unwrap(),
        );
        G2Affine::new_unchecked(x, y)
    };

    let e1 = Bn254::pairing(*p0, g2_gen);
    let e2 = Bn254::pairing(*p1, vk_g2);
    e1.0 * e2.0 == <Bn254 as Pairing>::TargetField::one()
}

/*───────────────────── main entry ───────────────────────*/

/// Shplonk verification (batch opening over BN254)
pub fn verify_shplonk(
    proof: &Proof,
    vk: &VerificationKey,
    tx: &Transcript,
) -> Result<(), String> {
    /*── 1) r^{2^i} ───────────────────────────────────*/
    let log_n = vk.log_circuit_size as usize;
    let n_sum = proof.sumcheck_evaluations.len();
    let mut r_pows = Vec::with_capacity(log_n);
    r_pows.push(tx.gemini_r);
    for i in 1..log_n { r_pows.push(r_pows[i - 1] * r_pows[i - 1]); }

    #[cfg(not(feature = "no-trace"))]
    {
        println!("===== Step-1 parameters =====");
        dbg_fr("gemini_r", &tx.gemini_r);
        dbg_vec("r_pow", &r_pows);
        println!("==============================");
    }

    /*── 2) 配列確保 ───────────────────────────────*/
    let total = 1 + n_sum + log_n + 1 + 1;
    print!("totalの数={}", total);
    let mut scalars = vec![Fr::zero(); total];
    let mut coms    = vec![G1Point { x: Fq::zero(), y: Fq::zero() }; total];

    /*── 3) バッチング係数 ─────────────────────────*/
    let pos0 = (tx.shplonk_z - r_pows[0]).inverse();
    let neg0 = (tx.shplonk_z + r_pows[0]).inverse();
    let unshifted = pos0 + tx.shplonk_nu * neg0;
    let shifted   = tx.gemini_r.inverse() * (pos0 - tx.shplonk_nu * neg0);

    #[cfg(not(feature = "no-trace"))]
    {
        dbg_fr("pos0"      , &pos0);
        dbg_fr("neg0"      , &neg0);
        dbg_fr("unshifted" , &unshifted);
        dbg_fr("shifted"   , &shifted);
    }

    /*── 4) shplonk_Q ─────────────────────────────*/
    scalars[0] = Fr::one();
    coms[0]    = proof.shplonk_q.clone();

    /*── 5) sumcheck evals に重み付け ─────────────*/
    let mut rho_pow = Fr::one();
    let mut eval_acc = Fr::zero();
    for (idx, eval) in proof.sumcheck_evaluations.iter().enumerate() {
        let scalar = if idx < NUMBER_UNSHIFTED { -unshifted } else { -shifted } * rho_pow;
        scalars[1 + idx] = scalar;
        eval_acc = eval_acc + *eval * rho_pow;
        rho_pow = rho_pow * tx.rho;
    }

    #[cfg(not(feature = "no-trace"))]
    {
        for i in 0..4 { dbg_fr(&format!("scalar[{i}]"), &scalars[1 + i]); }
        dbg_fr("eval_acc_end", &eval_acc);
    }

    /*── 6) VK / proof commitments ロード ─────────*/
    {
        let mut j = 1;
        macro_rules! push { ($f:ident) => {{ coms[j] = vk.$f.clone(); j += 1; }}}
        push!(qm); push!(qc); push!(ql); push!(qr);
        push!(qo); push!(q4);
        push!(q_lookup); push!(q_arith); push!(q_range); push!(q_elliptic);
        push!(q_aux); push!(q_poseidon2_external); push!(q_poseidon2_internal);
        push!(s1); push!(s2); push!(s3); push!(s4);
        push!(id1); push!(id2); push!(id3); push!(id4);
        push!(t1); push!(t2); push!(t3); push!(t4);
        push!(lagrange_first); push!(lagrange_last);

        coms[j] = proof.w1.clone(); j += 1;
        coms[j] = proof.w2.clone(); j += 1;
        coms[j] = proof.w3.clone(); j += 1;
        coms[j] = proof.w4.clone(); j += 1;
        coms[j] = proof.z_perm.clone(); j += 1;
        coms[j] = proof.lookup_inverses.clone(); j += 1;
        coms[j] = proof.lookup_read_counts.clone(); j += 1;
        coms[j] = proof.lookup_read_tags.clone(); j += 1;

        coms[j] = proof.w1.clone(); j += 1;
        coms[j] = proof.w2.clone(); j += 1;
        coms[j] = proof.w3.clone(); j += 1;
        coms[j] = proof.w4.clone(); j += 1;
        coms[j] = proof.z_perm.clone(); j += 1;
    }

    let mut fold_pos = vec![Fr::zero(); log_n];
    let mut cur = eval_acc;
    for j in (1..=log_n).rev() {
        let r2  = r_pows[j - 1];
        let u   = tx.sumcheck_u_challenges[j - 1];
        let num = r2 * cur * Fr::from_u64(2)
            - proof.gemini_a_evaluations[j - 1] * (r2 * (Fr::one() - u) - u);
        let den = r2 * (Fr::one() - u) + u;
        cur = num * den.inverse();
        fold_pos[j - 1] = cur;
    }

    #[cfg(not(feature = "no-trace"))]
    {
        dbg_fr("fold_pos_end", &fold_pos[0]);
    }

    let mut const_acc = fold_pos[0] * pos0
        + proof.gemini_a_evaluations[0] * tx.shplonk_nu * neg0;
    let mut v_pow = tx.shplonk_nu * tx.shplonk_nu;

    #[cfg(not(feature = "no-trace"))]
    {
        dbg_fr("const_acc_final", &const_acc);
    }

    let base = 1 + n_sum;
    println!("baseの数={}", base);
    for j in 1..log_n {
        #[cfg(not(feature = "no-trace"))]
        {
            println!("── fold round {j} ──────────────");
            dbg_fr("v_pow (before)", &v_pow);
        }

        let pos_inv = (tx.shplonk_z - r_pows[j]).inverse();
        let neg_inv = (tx.shplonk_z + r_pows[j]).inverse();
        let sp = v_pow * pos_inv;
        let sn = v_pow * tx.shplonk_nu * neg_inv;

        #[cfg(not(feature = "no-trace"))]
        {
            dbg_fr("pos_inv", &pos_inv);
            dbg_fr("neg_inv", &neg_inv);
            dbg_fr("scPos  ", &sp);
            dbg_fr("scNeg  ", &sn);
            dbg_fr("fold_pos[j]" , &fold_pos[j]);
            dbg_fr("A_eval ", &proof.gemini_a_evaluations[j]);
        }

        scalars[base + j - 1] = -(sp + sn);
        const_acc = const_acc
            + proof.gemini_a_evaluations[j] * sn
            + fold_pos[j] * sp;

        v_pow = v_pow * tx.shplonk_nu * tx.shplonk_nu;

        #[cfg(not(feature = "no-trace"))]
        {
            dbg_fr("const_acc", &const_acc);
            dbg_fr("v_pow (after)", &v_pow);
        }

        coms[base + j - 1] = proof.gemini_fold_comms[j - 1].clone();
    }

    let one_idx = base + log_n;
    println!("one_idxの数={}", one_idx);
    let gen = G1Projective::generator().into_affine();
    coms[one_idx]   = G1Point { x: gen.x, y: gen.y };
    scalars[one_idx] = const_acc;

    let q_idx      = one_idx + 1;
    println!("q_idxの数={}", q_idx);
    coms[q_idx]    = proof.kzg_quotient.clone();
    scalars[q_idx] = tx.shplonk_z;

    #[cfg(not(feature = "no-trace"))]
    {
        println!("===== Shplonk pre-MSM =====");
        println!("scalars.len() = {}", scalars.len());
        println!("coms.len()    = {}", coms.len());
        let base = 1 + NUMBER_UNSHIFTED;
        for k in 0..NUMBER_SHIFTED {
            dbg_fr(&format!("scalar_shifted[{k}]"), &scalars[base + k]);
        }
        println!("============================");
    }
    // println!("coms={:?}", coms);
    // println!("scalars={:?}", scalars);

    use crate::debug::dump_pairs;

    println!("========= FULL LIST =========");
    dump_pairs(&coms, &scalars, usize::MAX);
    println!("=============================");


    /*── 12) MSM + pairing ───────────────────*/
    let p0 = batch_mul(&coms, &scalars)?;
    let p1 = affine_checked(&negate(&proof.kzg_quotient))?;
    #[cfg(not(feature = "no-trace"))]
    {
        use ark_ff::BigInteger;
        println!("===== PAIRING-DEBUG =====");
        dbg_fr("scalar[z]" , &scalars[q_idx]);
        println!("P0.x = 0x{}", hex::encode(p0.x.into_bigint().to_bytes_be()));
        println!("P0.y = 0x{}", hex::encode(p0.y.into_bigint().to_bytes_be()));
        println!("P1.x = 0x{}", hex::encode(p1.x.into_bigint().to_bytes_be()));
        println!("P1.y = 0x{}", hex::encode(p1.y.into_bigint().to_bytes_be()));
        println!("=========================");
    }

    if pairing_check(&p0, &p1) {
        Ok(())
    } else {
        Err("Shplonk pairing check failed".into())
    }
}
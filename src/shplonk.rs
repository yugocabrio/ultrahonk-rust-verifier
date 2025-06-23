//! Shplonk batch-opening verifier for BN254
use crate::field::Fr;
use crate::types::{G1Point, Proof, Transcript, VerificationKey};

use ark_bn254::{Bn254, G1Affine, G1Projective, G2Affine, G2Projective, Fq, Fq2};
use ark_ec::{pairing::Pairing, CurveGroup, PrimeGroup};
use ark_ff::{Field, One, Zero, PrimeField, BigInteger256};

/// # 定数
pub const NUMBER_UNSHIFTED: usize = 35; // = 40 – 5
pub const NUMBER_SHIFTED: usize = 5;    // 後半 5 個

/*──────────────────────── helpers ────────────────────────*/

/// (x, y) → on-curve を確認した `G1Affine`
#[inline(always)]
fn affine_checked(pt: &G1Point) -> Result<G1Affine, String> {
    // G1Affine::new returns Option<Self>, but in arkworks it's a constructor, not a Result.
    // We check is_on_curve and is_in_correct_subgroup_assuming_on_curve for safety.
    let aff = G1Affine::new_unchecked(pt.x, pt.y);
    if aff.is_on_curve() && aff.is_in_correct_subgroup_assuming_on_curve() {
        Ok(aff)
    } else {
        Err("invalid G1 point (not on curve)".into())
    }
}
/// −P = (x, −y)
#[inline(always)]
fn negate(pt: &G1Point) -> G1Point {
    G1Point {
        x: pt.x,
        y: -pt.y,
    }
}

#[inline(always)]
fn is_dummy(pt: &G1Point) -> bool {
    pt.x.is_zero() && pt.y.is_zero()
}

/// ∑ sᵢ·Cᵢ  を安全に計算（invalid point があれば Err）
// 置き換え：batch_mul

fn batch_mul(coms: &[G1Point], scalars: &[Fr]) -> Result<G1Affine, String> {
    if coms.len() != scalars.len() {
        return Err("commitments / scalars length mismatch".into());
    }

    let mut acc = G1Projective::zero();

    for (c, s) in coms.iter().zip(scalars.iter()) {
        if s.is_zero() || (c.x.is_zero() && c.y.is_zero()) {
            continue;                               // スキップ
        }

        // on-curve チェック込み
        let aff = G1Affine::new_unchecked(c.x, c.y);
        if !aff.is_on_curve() || !aff.is_in_correct_subgroup_assuming_on_curve() {
            return Err("invalid G1 point (not on curve)".into());
        }

        // Projective へ → スカラー倍
        // Use scalar multiplication via ark_ec::VariableBaseMSM for efficiency and compatibility
        // But for simple loop, use .mul_bigint() from CurveGroup trait
        acc += G1Projective::from(aff).mul_bigint(s.0.into_bigint());
    }

    Ok(acc.into_affine())
}

/// e(P₀, G₂) · e(P₁, vk_G₂) == 1
fn pairing_check(p0: &G1Affine, p1: &G1Affine) -> bool {
    // BN254 の標準 G2 generator
    let g2_gen = G2Projective::generator().into_affine();

    // 固定 vk_G2（TS verifier と同値）
    let vk_g2 = {
        let x = Fq2::new(
            Fq::from_bigint(BigInteger256::new([
                0x260e_01b2_51f6_f1c7,
                0xe7ff_4e58_0791_dee8,
                0xea51_d87a_358e_038b,
                0x4efe_30fa_c093_83c1,
            ])).unwrap(),
            Fq::from_bigint(BigInteger256::new([
                0x1800_deef_121f_1e76,
                0x426a_0066_5e5c_4479,
                0x6743_22d4_f75e_dadd,
                0x46de_bd5c_d992_f6ed,
            ])).unwrap(),
        );
        let y = Fq2::new(
            Fq::from_bigint(BigInteger256::new([
                0x0906_89d0_585f_f075,
                0xec9e_99ad_690c_3395,
                0xbc4b_3133_70b3_8ef3,
                0x55ac_dadc_d122_975b,
            ])).unwrap(),
            Fq::from_bigint(BigInteger256::new([
                0x12c8_5ea5_db8c_6deb,
                0x4aab_7180_8dcb_408f,
                0xe3d1_e769_0c43_d37b,
                0x4ce6_cc01_66fa_7daa,
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
    // alias
    let log_n = vk.log_circuit_size as usize;
    let n_sum = proof.sumcheck_evaluations.len(); // (=40)

    /*── 1) r^{2^i} の前計算 ─────────────────────────────*/
    let mut r_pows = Vec::with_capacity(log_n);
    r_pows.push(tx.gemini_r);
    for i in 1..log_n {
        r_pows.push(r_pows[i - 1] * r_pows[i - 1]);
    }

    /*── 可視化ブロック ────────────────────────────────*/
    eprintln!("===== Step-1 parameters =====");
    for (i, p) in r_pows.iter().enumerate() {
        eprintln!("r^(2^{}) = {:?}", i, p);
    }
    eprintln!("==============================");

    /*── 2) 配列サイズを確保 ─────────────────────────────*/
    let total = 1           // shplonk_Q
        + n_sum            // 40 eval scalars
        + 40               // VK + proof commitments
        + log_n            // fold commitments
        + 1                // constant term [1]₁
        + 1;               // quotient commitment
    let mut scalars = vec![Fr::zero(); total];
    let mut coms    = vec![G1Point { x: Fq::zero(), y: Fq::zero() }; total];

    /*── 3) バッチング係数（unshifted / shifted）──────────*/
    let pos0 = (tx.shplonk_z - r_pows[0]).inverse();
    let neg0 = (tx.shplonk_z + r_pows[0]).inverse();
    let unshifted = pos0 + tx.shplonk_nu * neg0;
    let shifted   = tx.gemini_r.inverse() * (pos0 - tx.shplonk_nu * neg0);

    /*── 4) shplonk_Q ───────────────────────────────────*/
    scalars[0] = Fr::one();
    coms[0]    = proof.shplonk_q.clone();

    /*── 5) sumcheck evals を ρ-powers で重み付け ───────*/
    let mut rho_pow = Fr::one();
    let mut eval_acc = Fr::zero();
    for (idx, eval) in proof.sumcheck_evaluations.iter().enumerate() {
        let scalar = if idx < NUMBER_UNSHIFTED { -unshifted } else { -shifted } * rho_pow;
        scalars[1 + idx] = scalar;
        eval_acc = eval_acc + *eval * rho_pow;
        rho_pow = rho_pow * tx.rho;
    }

    /*── 6) VK commitmentsをロード ───────────────────────*/
    {
        let mut j = 1 + n_sum;
        macro_rules! push { ($f:ident) => {{ coms[j] = vk.$f.clone(); j += 1; }}}
        push!(qm); push!(qc); push!(ql); push!(qr);
        push!(qo); push!(q4);
        push!(q_lookup); push!(q_arith); push!(q_range); push!(q_aux);
        push!(q_elliptic); push!(q_poseidon2_external); push!(q_poseidon2_internal);
        push!(s1); push!(s2); push!(s3); push!(s4);
        push!(id1); push!(id2); push!(id3); push!(id4);
        push!(t1); push!(t2); push!(t3); push!(t4);
        push!(lagrange_first); push!(lagrange_last);

        // proof commitments (unshifted)
        coms[j] = proof.w1.clone(); j += 1;
        coms[j] = proof.w2.clone(); j += 1;
        coms[j] = proof.w3.clone(); j += 1;
        coms[j] = proof.w4.clone(); j += 1;
        coms[j] = proof.z_perm.clone(); j += 1;
        coms[j] = proof.lookup_inverses.clone(); j += 1;
        coms[j] = proof.lookup_read_counts.clone(); j += 1;
        coms[j] = proof.lookup_read_tags.clone(); j += 1;
        // shifted wires
        coms[j] = proof.w1.clone(); j += 1;
        coms[j] = proof.w2.clone(); j += 1;
        coms[j] = proof.w3.clone(); j += 1;
        coms[j] = proof.w4.clone(); j += 1;
        coms[j] = proof.z_perm.clone(); j += 1;
    }

    /*── 7) Gemini folding: fold_pos evals ──────────────*/
    let mut fold_pos = vec![Fr::zero(); log_n];
    let mut cur = eval_acc;
    for j in (1..=log_n).rev() {
        let r2 = r_pows[j - 1];
        let u  = tx.sumcheck_u_challenges[j - 1];
        let num = r2 * cur * Fr::from_u64(2)
            - proof.gemini_a_evaluations[j - 1] * (r2 * (Fr::one() - u) - u);
        let den = r2 * (Fr::one() - u) + u;
        cur = num * den.inverse();
        fold_pos[j - 1] = cur;
    }

    /*── 8) 定数項の蓄積 ────────────────────────────────*/
    let mut const_acc = fold_pos[0] * pos0
        + proof.gemini_a_evaluations[0] * tx.shplonk_nu * neg0;
    let mut v_pow = tx.shplonk_nu * tx.shplonk_nu;

    /*── 9) fold commitments ───────────────────────────*/
    let base = 1 + n_sum + 40;
    for j in 1..log_n {
        let pos_inv = (tx.shplonk_z - r_pows[j]).inverse();
        let neg_inv = (tx.shplonk_z + r_pows[j]).inverse();
        let sp = v_pow * pos_inv;
        let sn = v_pow * tx.shplonk_nu * neg_inv;
        scalars[base + j - 1] = -(sp + sn);
        const_acc = const_acc + proof.gemini_a_evaluations[j] * sn + fold_pos[j] * sp;
        v_pow = v_pow * tx.shplonk_nu * tx.shplonk_nu;
        coms[base + j - 1] = proof.gemini_fold_comms[j - 1].clone();
    }

    /*── 10) [1]₁ のスカラー = const_acc ────────────────*/
    let one_idx = base + log_n;
    let gen = G1Projective::generator().into_affine();
    coms[one_idx] = G1Point { x: gen.x, y: gen.y };
    scalars[one_idx] = const_acc;

    /*── 11) quotient commitment ───────────────────────*/
    let q_idx = one_idx + 1;
    coms[q_idx] = proof.kzg_quotient.clone();
    scalars[q_idx] = tx.shplonk_z;

    /*── 12) MSM + pairing チェック ────────────────────*/
    let p0 = batch_mul(&coms, &scalars)?;
    let p1 = affine_checked(&negate(&proof.kzg_quotient))?;
    if pairing_check(&p0, &p1) {
        Ok(())
    } else {
        Err("Shplonk pairing check failed".into())
    }
}
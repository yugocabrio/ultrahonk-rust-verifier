use std::{fs, path::Path};
use ultrahonk_rust_verifier::types::VerificationKey;

#[test]
fn vk_bytes_vs_json_match() -> Result<(), String> {
    let dir = Path::new("circuits/simple_circuit/target");
    let json = fs::read_to_string(dir.join("vk_fields.json")).map_err(|e| e.to_string())?;
    let vk_from_json: VerificationKey = ultrahonk_rust_verifier::utils::load_vk_from_json(&json);
    let vk_from_bytes = ultrahonk_rust_verifier::utils::load_vk_from_bytes_file(&dir.join("vk")).ok_or("bytes vk parse failed")?;

    macro_rules! assert_eq_pt {
        ($a:expr, $b:expr, $name:literal) => {{
            if $a.x != $b.x || $a.y != $b.y {
                return Err(format!("VK mismatch at {}", $name));
            }
        }};
    }

    assert_eq_pt!(vk_from_json.ql, vk_from_bytes.ql, "ql");
    assert_eq_pt!(vk_from_json.qr, vk_from_bytes.qr, "qr");
    assert_eq_pt!(vk_from_json.qo, vk_from_bytes.qo, "qo");
    assert_eq_pt!(vk_from_json.q4, vk_from_bytes.q4, "q4");
    assert_eq_pt!(vk_from_json.qm, vk_from_bytes.qm, "qm");
    assert_eq_pt!(vk_from_json.qc, vk_from_bytes.qc, "qc");
    assert_eq_pt!(vk_from_json.q_arith, vk_from_bytes.q_arith, "q_arith");
    assert_eq_pt!(vk_from_json.q_delta_range, vk_from_bytes.q_delta_range, "q_delta_range");
    assert_eq_pt!(vk_from_json.q_elliptic, vk_from_bytes.q_elliptic, "q_elliptic");
    assert_eq_pt!(vk_from_json.q_memory, vk_from_bytes.q_memory, "q_memory");
    assert_eq_pt!(vk_from_json.q_lookup, vk_from_bytes.q_lookup, "q_lookup");
    assert_eq_pt!(vk_from_json.q_poseidon2_external, vk_from_bytes.q_poseidon2_external, "q_poseidon2_external");
    assert_eq_pt!(vk_from_json.q_poseidon2_internal, vk_from_bytes.q_poseidon2_internal, "q_poseidon2_internal");
    assert_eq_pt!(vk_from_json.s1, vk_from_bytes.s1, "s1");
    assert_eq_pt!(vk_from_json.s2, vk_from_bytes.s2, "s2");
    assert_eq_pt!(vk_from_json.s3, vk_from_bytes.s3, "s3");
    assert_eq_pt!(vk_from_json.s4, vk_from_bytes.s4, "s4");
    assert_eq_pt!(vk_from_json.t1, vk_from_bytes.t1, "t1");
    assert_eq_pt!(vk_from_json.t2, vk_from_bytes.t2, "t2");
    assert_eq_pt!(vk_from_json.t3, vk_from_bytes.t3, "t3");
    assert_eq_pt!(vk_from_json.t4, vk_from_bytes.t4, "t4");
    assert_eq_pt!(vk_from_json.id1, vk_from_bytes.id1, "id1");
    assert_eq_pt!(vk_from_json.id2, vk_from_bytes.id2, "id2");
    assert_eq_pt!(vk_from_json.id3, vk_from_bytes.id3, "id3");
    assert_eq_pt!(vk_from_json.id4, vk_from_bytes.id4, "id4");
    assert_eq_pt!(vk_from_json.lagrange_first, vk_from_bytes.lagrange_first, "lagrange_first");
    assert_eq_pt!(vk_from_json.lagrange_last, vk_from_bytes.lagrange_last, "lagrange_last");

    Ok(())
}


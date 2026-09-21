//! The VRF test vectors published with `cardano-base`
//! (`cardano-crypto-praos/test_vectors/`), run against both VRF flavours.
//!
//! `vrf_ver03_*` are `PraosVRF` (draft-03) and `vrf_ver13_*` are
//! `PraosBatchCompatVRF` (draft-13, batch compatible). Each file gives a seed,
//! the expected verification key, the expected proof and the expected output for
//! a given input, so they pin down proving, verification and `proof_to_hash` at
//! the byte level.

use ouroboros_crypto_kit::vrf::{praos, praos_batch};

fn hex(s: &str) -> Vec<u8> {
    fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("invalid hex digit {:?}", c as char),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() % 2 == 0, "odd length hex string: {s}");
    b.chunks(2)
        .map(|p| (nibble(p[0]) << 4) | nibble(p[1]))
        .collect()
}

struct Vector {
    name: String,
    flavour: String,
    sk: Vec<u8>,
    pk: Vec<u8>,
    alpha: Vec<u8>,
    pi: Vec<u8>,
    beta: Vec<u8>,
}

fn parse(name: &str, content: &str) -> Vector {
    let mut fields = std::collections::HashMap::new();
    for line in content.lines() {
        if let Some((k, v)) = line.split_once(':') {
            fields.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    let get = |k: &str| -> String {
        fields
            .get(k)
            .unwrap_or_else(|| panic!("{name}: missing field {k}"))
            .clone()
    };
    // an empty input is spelled "empty" in these files
    let alpha_field = get("alpha");
    let alpha = if alpha_field == "empty" {
        Vec::new()
    } else {
        hex(&alpha_field)
    };
    Vector {
        name: name.to_string(),
        flavour: get("vrf"),
        sk: hex(&get("sk")),
        pk: hex(&get("pk")),
        alpha,
        pi: hex(&get("pi")),
        beta: hex(&get("beta")),
    }
}

fn vectors() -> Vec<Vector> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/vrf");
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("test vector directory")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("vrf_ver"))
        })
        .collect();
    entries.sort();
    assert!(!entries.is_empty(), "no test vectors found in {dir:?}");
    entries
        .iter()
        .map(|p| {
            let content = std::fs::read_to_string(p).expect("readable vector");
            parse(&p.file_name().unwrap().to_string_lossy(), &content)
        })
        .collect()
}

#[test]
fn all_cardano_base_vectors() {
    let mut seen03 = 0;
    let mut seen13 = 0;

    for v in vectors() {
        let seed: [u8; 32] = v.sk.clone().try_into().expect("32-byte seed");
        match v.flavour.as_str() {
            "PraosVRF" => {
                seen03 += 1;
                let sk = praos::SecretKey::from_seed(&seed);
                let pk = sk.public();
                assert_eq!(pk.as_bytes()[..], v.pk[..], "{}: public key", v.name);

                let proof = sk.prove(&v.alpha);
                assert_eq!(proof.as_bytes()[..], v.pi[..], "{}: proof", v.name);

                let output = praos::verify(&pk, &proof, &v.alpha)
                    .unwrap_or_else(|e| panic!("{}: verify failed: {e}", v.name));
                assert_eq!(output.as_bytes()[..], v.beta[..], "{}: output", v.name);

                // proof_to_hash on its own agrees with verification
                assert_eq!(
                    proof.to_hash().expect("hashes").as_bytes()[..],
                    v.beta[..],
                    "{}: proof_to_hash",
                    v.name
                );

                // and a proof taken straight from the file verifies too
                let parsed = praos::Proof::from_slice(&v.pi).expect("80-byte proof");
                assert_eq!(
                    praos::verify(&pk, &parsed, &v.alpha)
                        .expect("verifies")
                        .as_bytes()[..],
                    v.beta[..],
                    "{}: parsed proof",
                    v.name
                );
            }
            "PraosBatchCompatVRF" => {
                seen13 += 1;
                let sk = praos_batch::SecretKey::from_seed(&seed);
                let pk = sk.public();
                assert_eq!(pk.as_bytes()[..], v.pk[..], "{}: public key", v.name);

                let proof = sk.prove(&v.alpha);
                assert_eq!(proof.as_bytes()[..], v.pi[..], "{}: proof", v.name);

                let output = praos_batch::verify(&pk, &proof, &v.alpha)
                    .unwrap_or_else(|e| panic!("{}: verify failed: {e}", v.name));
                assert_eq!(output.as_bytes()[..], v.beta[..], "{}: output", v.name);

                assert_eq!(
                    proof.to_hash().expect("hashes").as_bytes()[..],
                    v.beta[..],
                    "{}: proof_to_hash",
                    v.name
                );

                let parsed = praos_batch::Proof::from_slice(&v.pi).expect("128-byte proof");
                assert_eq!(
                    praos_batch::verify(&pk, &parsed, &v.alpha)
                        .expect("verifies")
                        .as_bytes()[..],
                    v.beta[..],
                    "{}: parsed proof",
                    v.name
                );
            }
            other => panic!("{}: unknown vrf flavour {other}", v.name),
        }
    }

    assert_eq!(seen03, 7, "expected 7 draft-03 vectors");
    assert_eq!(seen13, 7, "expected 7 draft-13 vectors");
}

/// The 31 vectors libsodium itself ships for draft-03
/// (`test/default/vrf.c` of the IOHK fork). They cover a much wider range of
/// inputs than the cardano-base set, which is what makes them useful for the
/// Elligator2 path.
#[test]
fn libsodium_draft03_vectors() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/vrf/libsodium_vrf03.txt");
    let content = std::fs::read_to_string(path).expect("vector file");

    let mut count = 0;
    for line in content.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(f.len(), 5, "malformed line: {line}");
        let seed: [u8; 32] = hex(f[0]).try_into().expect("32-byte seed");
        let alpha = if f[4] == "-" { Vec::new() } else { hex(f[4]) };

        let sk = praos::SecretKey::from_seed(&seed);
        let pk = sk.public();
        assert_eq!(pk.as_bytes()[..], hex(f[1])[..], "public key: {line}");

        let proof = sk.prove(&alpha);
        assert_eq!(proof.as_bytes()[..], hex(f[2])[..], "proof: {line}");

        let output = praos::verify(&pk, &proof, &alpha).expect("verifies");
        assert_eq!(output.as_bytes()[..], hex(f[3])[..], "output: {line}");
        count += 1;
    }
    assert_eq!(count, 31, "expected 31 libsodium vectors");
}

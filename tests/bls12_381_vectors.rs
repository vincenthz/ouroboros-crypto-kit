//! BLS12-381 against published vectors.
//!
//! * `tests/data/bls12_381/rfc9380_hash_to_curve.txt` holds the ten
//!   `hash_to_curve` vectors of RFC 9380 appendices J.9.1 (G1) and J.10.1 (G2),
//!   extracted from the RFC text. They pin down `expand_message_xmd`,
//!   `hash_to_field`, the simplified SWU map, both isogenies and cofactor
//!   clearing.
//! * the compressed generator encodings are the ones every BLS12-381
//!   implementation agrees on (they appear in the ZCash serialisation spec, in
//!   `blst`, and in CIP-0381's examples), so they pin down the serialisation
//!   including its flag bits.

use ouroboros_crypto_kit::plutus::bls12_381::{miller_loop, BlsError, Scalar, G1, G2};

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

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}

const G1_DST: &[u8] = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
const G2_DST: &[u8] = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

#[test]
fn rfc9380_hash_to_curve_vectors() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/bls12_381/rfc9380_hash_to_curve.txt");
    let content = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));

    let mut g1_count = 0;
    let mut g2_count = 0;
    for line in content.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(f.len(), 4, "malformed row: {line}");
        let msg: Vec<u8> = if f[1] == "-" {
            Vec::new()
        } else {
            f[1].as_bytes().to_vec()
        };

        match f[0] {
            "G1" => {
                g1_count += 1;
                // the uncompressed serialisation is x || y, which is exactly
                // what the vector gives
                let p = G1::hash_to_group(&msg, G1_DST).expect("hashes");
                let serialised = p.serialize();
                assert_eq!(to_hex(&serialised[..48]), f[2], "G1 x for msg {:?}", f[1]);
                assert_eq!(to_hex(&serialised[48..]), f[3], "G1 y for msg {:?}", f[1]);

                // and the point survives a compression round trip
                assert_eq!(G1::uncompress(&p.compress()).unwrap(), p);
            }
            "G2" => {
                g2_count += 1;
                let (x_c0, x_c1) = f[2].split_once('|').expect("c0|c1");
                let (y_c0, y_c1) = f[3].split_once('|').expect("c0|c1");

                let q = G2::hash_to_group(&msg, G2_DST).expect("hashes");
                let s = q.serialize();
                // serialise writes the imaginary part first
                assert_eq!(to_hex(&s[..48]), x_c1, "G2 x.c1 for msg {:?}", f[1]);
                assert_eq!(to_hex(&s[48..96]), x_c0, "G2 x.c0 for msg {:?}", f[1]);
                assert_eq!(to_hex(&s[96..144]), y_c1, "G2 y.c1 for msg {:?}", f[1]);
                assert_eq!(to_hex(&s[144..]), y_c0, "G2 y.c0 for msg {:?}", f[1]);

                assert_eq!(G2::uncompress(&q.compress()).unwrap(), q);
            }
            other => panic!("unknown group {other}"),
        }
    }
    assert_eq!(g1_count, 5, "expected 5 G1 vectors");
    assert_eq!(g2_count, 5, "expected 5 G2 vectors");
}

/// The compressed generators, as published in the ZCash BLS12-381 serialisation
/// spec and used by `blst` and CIP-0381.
#[test]
fn compressed_generators() {
    let g1 = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    let g2 = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e\
              024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";

    assert_eq!(to_hex(&G1::generator().compress()), g1);
    assert_eq!(to_hex(&G2::generator().compress()), g2);

    // and they parse back
    assert_eq!(G1::uncompress(&hex(g1)).unwrap(), G1::generator());
    assert_eq!(G2::uncompress(&hex(g2)).unwrap(), G2::generator());

    // the infinity encodings are 0xc0 followed by zeros
    let mut inf1 = [0u8; 48];
    inf1[0] = 0xc0;
    assert_eq!(G1::zero().compress()[..], inf1[..]);
    let mut inf2 = [0u8; 96];
    inf2[0] = 0xc0;
    assert_eq!(G2::zero().compress()[..], inf2[..]);
}

/// A point on the curve but outside the prime-order subgroup must be rejected,
/// which is the check that distinguishes `uncompress` from mere parsing.
#[test]
fn uncompress_rejects_points_outside_the_subgroup() {
    // A G1 point of order 3 (the cofactor of G1 is 3 * 11^2 * 10177^2 * ...):
    // rather than hard-code one, search for an x whose y exists and whose point
    // is not killed by r.
    let mut found = false;
    for i in 0u32..200 {
        let mut bytes = [0u8; 48];
        bytes[44..].copy_from_slice(&i.to_be_bytes());
        bytes[0] |= 0x80;
        match G1::uncompress(&bytes) {
            Err(BlsError::NotInGroup) => {
                found = true;
                break;
            }
            _ => continue,
        }
    }
    assert!(
        found,
        "expected to find a curve point outside the subgroup among small x"
    );
}

/// The pairing identity a BLS signature verification relies on, end to end
/// through the Plutus-facing API.
#[test]
fn bls_signature_verification() {
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let sk = Scalar::from_be_bytes_mod_order(&hex(
        "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
    ));
    let pk = G2::generator().scalar_mul(&sk);

    let msg = b"blst is such a blast";
    let h = G1::hash_to_group(msg, dst).unwrap();
    let sig = h.scalar_mul(&sk);

    // e(H(m), pk) == e(sig, G2)
    assert!(miller_loop(&h, &pk).final_verify(&miller_loop(&sig, &G2::generator())));

    // the aggregate form: e(H1, pk1) * e(H2, pk2) == e(sig1 + sig2, G2) when
    // both signatures come from the same message
    let sk2 = Scalar::from_u64(999);
    let pk2 = G2::generator().scalar_mul(&sk2);
    let sig2 = h.scalar_mul(&sk2);
    let aggregate = miller_loop(&h, &pk).mul(&miller_loop(&h, &pk2));
    assert!(aggregate.final_verify(&miller_loop(&sig.add(&sig2), &G2::generator())));

    // tampering with the message breaks it
    let wrong = G1::hash_to_group(b"blst is such a blast!", dst).unwrap();
    assert!(!miller_loop(&wrong, &pk).final_verify(&miller_loop(&sig, &G2::generator())));
}

//! BLS12-381 against the Ethereum BLS test vectors
//! (`ethereum/bls12-381-tests`, release v0.1.2), which were generated with
//! independent implementations (`py_ecc` / `blst`).
//!
//! They exercise the whole stack the Plutus builtins are made of, and in
//! particular the rejection behaviour of `uncompress`, which is where an
//! implementation is most likely to differ:
//!
//! * `deserialization_G1` / `deserialization_G2` — every malformed compressed
//!   encoding: wrong flag bits, `x` equal to or above the modulus, a point off
//!   the curve, a point on the curve but outside the subgroup, an infinity
//!   encoding with a non-zero payload, wrong lengths;
//! * `sign` — `sk * hash_to_G2(msg)`, compared as compressed bytes, so
//!   hash-to-curve, scalar multiplication and compression all have to agree;
//! * `verify` / `aggregate` / `aggregate_verify` — the pairing checks, through
//!   `millerLoop` / `mulMlResult` / `finalVerify`.
//!
//! The BLS scheme here is "minimal-pubkey-size" with proof of possession (the
//! `py_ecc` `G2ProofOfPossession` the generator uses): public keys are G1
//! points, signatures are G2 points, and messages are hashed to G2 with the DST
//! `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`.

use ouroboros_crypto_kit::plutus::bls12_381::{miller_loop, MlResult, Scalar, G1, G2};

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

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

fn rows(name: &str) -> Vec<Vec<String>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/bls12_381")
        .join(name);
    let content = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
    content
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.split_whitespace().map(str::to_string).collect())
        .collect()
}

/// `KeyValidate` of the BLS signature draft: a public key must decode, be in
/// the subgroup (which `uncompress` checks) and not be the identity.
fn key_validate(bytes: &[u8]) -> Option<G1> {
    let pk = G1::uncompress(bytes).ok()?;
    if pk.is_zero() {
        None
    } else {
        Some(pk)
    }
}

/// `CoreVerify`: `e(H(msg), pk) == e(sig, G1)`.
fn core_verify(pk: &G1, msg: &[u8], sig: &G2) -> bool {
    let h = G2::hash_to_group(msg, DST).expect("dst fits");
    miller_loop(pk, &h).final_verify(&miller_loop(&G1::generator(), sig))
}

#[test]
fn deserialization_g1() {
    let rows = rows("eth_deserialization_g1.txt");
    assert_eq!(rows.len(), 13);
    for r in rows {
        let (name, hexstr, expected) = (&r[0], &r[1], r[2] == "true");
        let bytes = if hexstr == "-" {
            Vec::new()
        } else {
            hex(hexstr)
        };
        let got = G1::uncompress(&bytes);
        assert_eq!(
            got.is_ok(),
            expected,
            "{name}: expected ok = {expected}, got {got:?}"
        );
        if let Ok(p) = got {
            // whatever we accepted must round trip to the same bytes
            assert_eq!(to_hex(&p.compress()), *hexstr, "{name}: round trip");
        }
    }
}

#[test]
fn deserialization_g2() {
    let rows = rows("eth_deserialization_g2.txt");
    assert_eq!(rows.len(), 15);
    for r in rows {
        let (name, hexstr, expected) = (&r[0], &r[1], r[2] == "true");
        let bytes = if hexstr == "-" {
            Vec::new()
        } else {
            hex(hexstr)
        };
        let got = G2::uncompress(&bytes);
        assert_eq!(
            got.is_ok(),
            expected,
            "{name}: expected ok = {expected}, got {got:?}"
        );
        if let Ok(p) = got {
            assert_eq!(to_hex(&p.compress()), *hexstr, "{name}: round trip");
        }
    }
}

#[test]
fn sign() {
    let rows = rows("eth_sign.txt");
    assert_eq!(rows.len(), 10);
    let mut signed = 0;
    for r in rows {
        let (name, privkey, message, expected) = (&r[0], &r[1], &r[2], &r[3]);
        let msg = if message == "-" {
            Vec::new()
        } else {
            hex(message)
        };
        let sk_bytes = hex(privkey);

        // the vectors' invalid cases are a zero secret key, which the scheme
        // rejects
        let sk = Scalar::from_be_bytes_mod_order(&sk_bytes);
        if expected == "null" {
            assert!(sk.is_zero(), "{name}: expected an invalid key");
            continue;
        }
        assert!(!sk.is_zero(), "{name}: key should be valid");

        let sig = G2::hash_to_group(&msg, DST).unwrap().scalar_mul(&sk);
        assert_eq!(to_hex(&sig.compress()), *expected, "{name}");
        signed += 1;
    }
    assert!(signed >= 6, "only {signed} signatures produced");
}

#[test]
fn verify() {
    let rows = rows("eth_verify.txt");
    assert_eq!(rows.len(), 29);
    let mut valid = 0;
    for r in rows {
        let (name, pubkey, message, signature, expected) =
            (&r[0], &r[1], &r[2], &r[3], r[4] == "true");
        let msg = if message == "-" {
            Vec::new()
        } else {
            hex(message)
        };

        let got = match (key_validate(&hex(pubkey)), G2::uncompress(&hex(signature))) {
            (Some(pk), Ok(sig)) => core_verify(&pk, &msg, &sig),
            _ => false,
        };
        assert_eq!(got, expected, "{name}: expected {expected}, got {got}");
        if expected {
            valid += 1;
        }
    }
    assert!(valid >= 8, "only {valid} valid signatures exercised");
}

#[test]
fn aggregate() {
    let rows = rows("eth_aggregate.txt");
    assert_eq!(rows.len(), 6);
    for r in rows {
        let (name, sigs, expected) = (&r[0], &r[1], &r[2]);
        if sigs == "-" {
            // aggregating nothing is invalid in the scheme, even though the
            // group has an identity
            assert_eq!(expected, "null", "{name}");
            continue;
        }
        let mut acc = G2::zero();
        let mut ok = true;
        for s in sigs.split(',') {
            match G2::uncompress(&hex(s)) {
                Ok(p) => acc = acc.add(&p),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if expected == "null" {
            assert!(!ok, "{name}: expected an invalid input");
        } else {
            assert!(ok, "{name}: inputs should parse");
            assert_eq!(to_hex(&acc.compress()), *expected, "{name}");
        }
    }
}

#[test]
fn aggregate_verify() {
    let rows = rows("eth_aggregate_verify.txt");
    assert_eq!(rows.len(), 5);
    for r in rows {
        let (name, pubkeys, msgs, signature, expected) =
            (&r[0], &r[1], &r[2], &r[3], r[4] == "true");

        let sig = match G2::uncompress(&hex(signature)) {
            Ok(s) => s,
            Err(_) => {
                assert!(!expected, "{name}: signature should parse");
                continue;
            }
        };

        if pubkeys == "-" {
            // no keys and no messages: only the identity signature could
            // verify, and the scheme rejects that anyway
            assert!(!expected, "{name}");
            continue;
        }

        let keys: Vec<&str> = pubkeys.split(',').collect();
        let messages: Vec<&str> = msgs.split(',').collect();
        assert_eq!(keys.len(), messages.len(), "{name}: mismatched lengths");

        // the aggregate check is a product of pairings:
        // prod_i e(H(msg_i), pk_i) == e(sig, G1)
        let mut product: Option<MlResult> = None;
        let mut all_keys_valid = true;
        for (pk_hex, msg_hex) in keys.iter().zip(messages.iter()) {
            let pk = match key_validate(&hex(pk_hex)) {
                Some(pk) => pk,
                None => {
                    all_keys_valid = false;
                    break;
                }
            };
            let msg = if *msg_hex == "-" {
                Vec::new()
            } else {
                hex(msg_hex)
            };
            let h = G2::hash_to_group(&msg, DST).unwrap();
            let term = miller_loop(&pk, &h);
            product = Some(match product {
                None => term,
                Some(acc) => acc.mul(&term),
            });
        }

        let got = all_keys_valid
            && product
                .map(|p| p.final_verify(&miller_loop(&G1::generator(), &sig)))
                .unwrap_or(false);
        assert_eq!(got, expected, "{name}: expected {expected}, got {got}");
    }
}

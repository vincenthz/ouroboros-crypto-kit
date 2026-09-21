//! The official BIP-340 test vectors, which are what `libsecp256k1` (and
//! therefore Plutus's `verifySchnorrSecp256k1Signature`) is tested against.
//!
//! The file is `bip-0340/test-vectors.csv` from the BIPs repository, unmodified.
//! It deliberately includes malformed inputs — keys that are not on the curve,
//! `r` equal to the field modulus, `s` equal to the group order, points at
//! infinity — so it pins down the rejection behaviour and not just the happy
//! path.

use ouroboros_crypto_kit::plutus::secp256k1::{verify_schnorr, Secp256k1Error};

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

#[test]
fn bip340_verification_vectors() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/secp256k1/bip340-test-vectors.csv");
    let content = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));

    let mut lines = content.lines();
    let header = lines.next().expect("header");
    assert!(
        header.starts_with("index,secret key,public key"),
        "unexpected header"
    );

    let mut checked = 0;
    let mut positive = 0;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split(',').collect();
        assert!(f.len() >= 7, "malformed row: {line}");
        let index = f[0];
        let pk = hex(f[2]);
        let msg = hex(f[4]);
        let sig = hex(f[5]);
        let expected = match f[6] {
            "TRUE" => true,
            "FALSE" => false,
            other => panic!("row {index}: unknown result {other}"),
        };
        let comment = f.get(7).copied().unwrap_or("");

        let got = verify_schnorr(&pk, &msg, &sig);
        assert_eq!(
            got.is_ok(),
            expected,
            "row {index} ({comment}): expected {expected}, got {got:?}"
        );
        checked += 1;
        if expected {
            positive += 1;
        }
    }

    // 19 rows in the current file, 5 of which must verify
    assert!(checked >= 15, "only {checked} rows checked");
    assert!(positive >= 4, "only {positive} positive rows checked");
}

/// Wycheproof's secp256k1/SHA-256 ECDSA vectors, in P1363 (`r || s`) form,
/// which is the encoding Plutus uses.
///
/// Wycheproof judges plain ECDSA, so it marks a high-`s` signature *valid*;
/// `libsecp256k1` — and therefore the Plutus builtin — rejects it. The
/// expectation is adjusted accordingly, which also means these vectors pin down
/// the malleability rule on 30-odd real signatures rather than a synthetic one.
#[test]
fn wycheproof_ecdsa_vectors() {
    // (n-1)/2, big-endian: an s above this is "high"
    const HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/secp256k1/wycheproof_ecdsa_p1363.txt");
    let content = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));

    let mut checked = 0;
    let mut low_s_valid = 0;
    let mut high_s_rejected = 0;
    for line in content.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        assert!(f.len() >= 5, "malformed row: {line}");
        let tc = f[0];
        let pk = hex(f[1]);
        let msg = if f[2] == "-" { Vec::new() } else { hex(f[2]) };
        let sig = if f[3] == "-" { Vec::new() } else { hex(f[3]) };
        let wycheproof_valid = match f[4] {
            "valid" => true,
            "invalid" => false,
            other => panic!("tc {tc}: unexpected result {other}"),
        };
        let comment = f.get(6).copied().unwrap_or("");

        let digest = ouroboros_crypto_kit::hash::sha256(&msg);

        let high_s = sig.len() == 64 && sig[32..] > HALF_ORDER[..];
        let expected = wycheproof_valid && !high_s;

        let got = ouroboros_crypto_kit::plutus::secp256k1::verify_ecdsa(&pk, &digest, &sig);
        assert_eq!(
            got.is_ok(),
            expected,
            "tc {tc} ({comment}): expected {expected} (wycheproof {wycheproof_valid}, high_s {high_s}), got {got:?}"
        );

        checked += 1;
        if expected {
            low_s_valid += 1;
        }
        if wycheproof_valid && high_s {
            high_s_rejected += 1;
        }
    }

    // of the 252 vectors, 95 are signatures that must verify and 72 are
    // otherwise-valid signatures rejected for malleability
    assert_eq!(checked, 252, "expected 252 vectors");
    assert_eq!(low_s_valid, 95, "accepted signatures");
    assert_eq!(high_s_rejected, 72, "malleable signatures rejected");
}

#[test]
fn schnorr_rejects_wrong_lengths() {
    let pk = hex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
    let sig = vec![0u8; 64];
    assert_eq!(
        verify_schnorr(&pk[..31], b"", &sig).unwrap_err(),
        Secp256k1Error::InvalidPublicKey
    );
    assert_eq!(
        verify_schnorr(&pk, b"", &sig[..63]).unwrap_err(),
        Secp256k1Error::InvalidSignature
    );
}

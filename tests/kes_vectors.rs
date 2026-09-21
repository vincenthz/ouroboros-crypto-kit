//! KES interoperability with `cardano-base`.
//!
//! The `.bin` files in `tests/data/kes` were produced by the Haskell
//! implementation with the following program (the seed is the ASCII string
//! `"test string of 32 byte of lenght"`, the message `"test message"`):
//!
//! ```haskell
//! seed  = mkSeedFromBytes $ Bytechar.pack "test string of 32 byte of lenght"
//! kesSk = genKeyKES @(Sum6KES Ed25519DSIGN Blake2b_256) seed
//! ...
//! B.writeFile "key6.bin"        (rawSerialiseSignKeyKES kesSk)
//! B.writeFile "key6Sig.bin"     (rawSerialiseSigKES (signKES () 0 message kesSk))
//! B.writeFile "key6update1.bin" (rawSerialiseSignKeyKES kesSkOneUpdate)
//! B.writeFile "key6Sig5.bin"    (rawSerialiseSigKES (signKES () 5 message kesSkFiveUpdate))
//! ```
//!
//! They therefore pin the key serialisation, the seed expansion, the evolution
//! and the signature encoding of both `SumKES` and `CompactSumKES` against the
//! implementation the node runs.

use ouroboros_crypto_kit::kes::{CompactSignature, CompactSumKes, Signature, SumKes};

const SEED: &[u8; 32] = b"test string of 32 byte of lenght";
const MESSAGE: &[u8] = b"test message";

fn data(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/kes")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {path:?}: {e}"))
}

fn seed() -> [u8; 32] {
    *SEED
}

#[test]
fn sum_key_serialisation_depth_1_and_6() {
    let sk1 = SumKes::from_seed(1, &mut seed()).unwrap();
    assert_eq!(sk1.as_bytes(), &data("key1.bin")[..], "Sum1KES key");

    let sk6 = SumKes::from_seed(6, &mut seed()).unwrap();
    assert_eq!(sk6.as_bytes(), &data("key6.bin")[..], "Sum6KES key");

    // depth 0 is the bare Ed25519 seed
    let sk0 = SumKes::from_seed(0, &mut seed()).unwrap();
    assert_eq!(sk0.as_bytes(), &data("key0.bin")[..], "Sum0KES key");
}

#[test]
fn sum_evolution_matches_haskell() {
    let mut sk = SumKes::from_seed(6, &mut seed()).unwrap();
    sk.update().unwrap();
    assert_eq!(
        sk.as_bytes(),
        &data("key6update1.bin")[..],
        "Sum6KES after one update"
    );

    for _ in 1..5 {
        sk.update().unwrap();
    }
    assert_eq!(sk.period(), 5);
    assert_eq!(
        sk.as_bytes(),
        &data("key6update5.bin")[..],
        "Sum6KES after five updates"
    );
}

#[test]
fn sum_signatures_match_haskell() {
    let sk = SumKes::from_seed(6, &mut seed()).unwrap();
    let vk = sk.public();
    let sig = sk.sign(MESSAGE);
    assert_eq!(
        sig.as_bytes(),
        &data("key6Sig.bin")[..],
        "Sum6KES signature at period 0"
    );
    assert!(sig.verify(0, &vk, MESSAGE).is_ok());

    let mut sk = SumKes::from_seed(6, &mut seed()).unwrap();
    for _ in 0..5 {
        sk.update().unwrap();
    }
    let sig5 = sk.sign(MESSAGE);
    assert_eq!(
        sig5.as_bytes(),
        &data("key6Sig5.bin")[..],
        "Sum6KES signature at period 5"
    );
    assert!(sig5.verify(5, &vk, MESSAGE).is_ok());
    assert!(sig5.verify(4, &vk, MESSAGE).is_err());

    // signatures read back from the Haskell files verify as well
    let parsed = Signature::from_bytes(6, &data("key6Sig.bin")).unwrap();
    assert!(parsed.verify(0, &vk, MESSAGE).is_ok());
}

#[test]
fn compact_key_serialisation_depth_1_and_6() {
    let sk1 = CompactSumKes::from_seed(1, &mut seed()).unwrap();
    assert_eq!(
        sk1.as_bytes(),
        &data("compactkey1.bin")[..],
        "CompactSum1KES key"
    );

    let sk6 = CompactSumKes::from_seed(6, &mut seed()).unwrap();
    assert_eq!(
        sk6.as_bytes(),
        &data("compactkey6.bin")[..],
        "CompactSum6KES key"
    );

    let sk0 = CompactSumKes::from_seed(0, &mut seed()).unwrap();
    assert_eq!(
        sk0.as_bytes(),
        &data("compactkey0.bin")[..],
        "CompactSum0KES key"
    );
}

#[test]
fn compact_evolution_matches_haskell() {
    let mut sk = CompactSumKes::from_seed(6, &mut seed()).unwrap();
    sk.update().unwrap();
    assert_eq!(
        sk.as_bytes(),
        &data("compactkey6update1.bin")[..],
        "CompactSum6KES after one update"
    );

    for _ in 1..5 {
        sk.update().unwrap();
    }
    assert_eq!(
        sk.as_bytes(),
        &data("compactkey6update5.bin")[..],
        "CompactSum6KES after five updates"
    );
}

#[test]
fn compact_signatures_match_haskell() {
    let sk = CompactSumKes::from_seed(6, &mut seed()).unwrap();
    let vk = sk.public();
    let sig = sk.sign(MESSAGE);
    assert_eq!(
        sig.as_bytes(),
        &data("compactkey6Sig.bin")[..],
        "CompactSum6KES signature at period 0"
    );
    assert!(sig.verify(0, &vk, MESSAGE).is_ok());

    let mut sk = CompactSumKes::from_seed(6, &mut seed()).unwrap();
    for _ in 0..5 {
        sk.update().unwrap();
    }
    let sig5 = sk.sign(MESSAGE);
    assert_eq!(
        sig5.as_bytes(),
        &data("compactkey6Sig5.bin")[..],
        "CompactSum6KES signature at period 5"
    );
    assert!(sig5.verify(5, &vk, MESSAGE).is_ok());
    assert!(sig5.verify(4, &vk, MESSAGE).is_err());

    let parsed = CompactSignature::from_bytes(6, &data("compactkey6Sig5.bin")).unwrap();
    assert!(parsed.verify(5, &vk, MESSAGE).is_ok());
}

#[test]
fn sum_and_compact_share_key_material() {
    // the two constructions differ only in their signatures
    let sum = SumKes::from_seed(6, &mut seed()).unwrap();
    let compact = CompactSumKes::from_seed(6, &mut seed()).unwrap();
    assert_eq!(sum.as_bytes(), compact.as_bytes());
    assert_eq!(sum.public(), compact.public());
}

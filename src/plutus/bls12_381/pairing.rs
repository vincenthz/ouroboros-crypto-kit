//! The optimal ate pairing, split into the two halves Plutus exposes
//! separately: [`miller_loop`] and the final exponentiation hidden inside
//! [`MlResult::final_verify`].
//!
//! It exposes the loop and the final exponentiation as separate steps, which is exactly the shape Plutus needs:
//! `bls12_381_millerLoop`, `bls12_381_mulMlResult` and `bls12_381_finalVerify`
//! are three builtins with the `Fp12` living in between, so `pairing()` — which
//! fuses them — cannot serve.
//!
//! # What has to match `blst`, and what does not
//!
//! Plutus can never observe the bytes of an `MlResult`: the only things it can
//! do with one are multiply it ([`MlResult::mul`]) and compare two of them
//! ([`MlResult::final_verify`]). So this implementation only has to agree with
//! `blst` on that comparison, not on the representation.
//!
//! The comparison itself is one final exponentiation rather than two: the final
//! exponentiation is a power map, so `e(a) == e(b)` exactly when
//! `e(a · b⁻¹) == 1`.

use eccoxide::curve::bls12_381::pairing::{self, MillerLoopResult};
use eccoxide::curve::bls12_381::{Fp12, g1, g2};

/// The result of a Miller loop: an element of `Fp12` that has not been through
/// the final exponentiation yet (Plutus calls this type `MlResult`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MlResult(Fp12);

impl MlResult {
    /// `bls12_381_mulMlResult`: multiply two Miller loop results.
    pub fn mul(&self, other: &MlResult) -> MlResult {
        MlResult(&self.0 * &other.0)
    }

    /// `bls12_381_finalVerify`: whether the two results have the same image
    /// under the final exponentiation, i.e. whether the products of pairings
    /// they stand for are equal.
    pub fn final_verify(&self, other: &MlResult) -> bool {
        final_exponentiation(&(&self.0 * &other.0.inverse())) == Fp12::ONE
    }

    /// The underlying `Fp12` element, for testing.
    #[cfg(test)]
    pub(crate) fn inner(&self) -> &Fp12 {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn from_fp12(f: Fp12) -> Self {
        MlResult(f)
    }
}

/// `bls12_381_millerLoop`: the Miller loop `f_{|x|, Q}(P)`.
///
/// A point at infinity in either argument gives the identity, which is the value
/// of the pairing there — and which eccoxide's affine-only entry point cannot
/// represent, so it is handled here.
pub fn miller_loop(p: &g1::Point, q: &g2::Point) -> MlResult {
    match (p.to_affine(), q.to_affine()) {
        (Some(p), Some(q)) => MlResult(pairing::miller_loop(&p, &q).0),
        _ => MlResult(Fp12::ONE),
    }
}

/// The final exponentiation `f^((p¹² - 1)/r)`.
fn final_exponentiation(f: &Fp12) -> Fp12 {
    MillerLoopResult(f.clone()).final_exponentiation()
}

/// The pairing itself, for tests that want a single value rather than Plutus's
/// two-step form.
#[cfg(test)]
fn pairing(p: &g1::Point, q: &g2::Point) -> Fp12 {
    final_exponentiation(miller_loop(p, q).inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use eccoxide::curve::bls12_381::Scalar;
    use eccoxide::params::bls12_381::{FINAL_EXP_BYTES, ORDER_BYTES};

    fn g1_mul(k: u64) -> g1::Point {
        g1::Point::mul_base(&Scalar::from_u64(k))
    }
    fn g2_mul(k: u64) -> g2::Point {
        g2::Point::mul_base(&Scalar::from_u64(k))
    }

    #[test]
    fn the_two_step_form_agrees_with_eccoxides_pairing() {
        let p = g1_mul(3);
        let q = g2_mul(5);
        assert_eq!(
            pairing(&p, &q),
            eccoxide::curve::bls12_381::pairing::pairing(
                &p.to_affine().unwrap(),
                &q.to_affine().unwrap(),
            )
        );
    }

    #[test]
    fn fast_final_exponentiation_matches_the_naive_one() {
        let f = miller_loop(&g1_mul(7), &g2_mul(11)).inner().clone();
        assert_eq!(final_exponentiation(&f), f.pow_bytes(&FINAL_EXP_BYTES));
    }

    #[test]
    fn non_degenerate_and_in_the_target_group() {
        let e = pairing(&g1::Point::GENERATOR, &g2::Point::GENERATOR);
        assert_ne!(e, Fp12::ONE, "pairing is degenerate");
        assert_eq!(e.pow_bytes(&ORDER_BYTES), Fp12::ONE, "e^r != 1");
    }

    #[test]
    fn bilinear() {
        let a = 0x9e3779b97f4a7c15u64;
        let b = 0x1234_5678_9abc_def0u64;

        let base = pairing(&g1::Point::GENERATOR, &g2::Point::GENERATOR);
        let ea = pairing(&g1_mul(a), &g2::Point::GENERATOR);
        let eb = pairing(&g1::Point::GENERATOR, &g2_mul(b));

        assert_eq!(ea, base.pow_bytes(&Scalar::from_u64(a).to_bytes_be()));
        assert_eq!(eb, base.pow_bytes(&Scalar::from_u64(b).to_bytes_be()));

        // e(aP, bQ) == e(P, Q)^(ab)
        let ab = &Scalar::from_u64(a) * &Scalar::from_u64(b);
        assert_eq!(
            pairing(&g1_mul(a), &g2_mul(b)),
            base.pow_bytes(&ab.to_bytes_be())
        );
    }

    #[test]
    fn additive_in_each_argument() {
        // e(P1 + P2, Q) == e(P1, Q) * e(P2, Q)
        let q = g2_mul(9);
        let lhs = pairing(&g1_mul(3 + 5), &q);
        let rhs = &pairing(&g1_mul(3), &q) * &pairing(&g1_mul(5), &q);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn infinity_pairs_to_one() {
        assert_eq!(
            miller_loop(&g1::Point::INFINITY, &g2_mul(3)),
            MlResult(Fp12::ONE)
        );
        assert_eq!(
            miller_loop(&g1_mul(3), &g2::Point::INFINITY),
            MlResult(Fp12::ONE)
        );
    }

    #[test]
    fn final_verify_matches_the_pairing_identity() {
        // e(aP, Q) == e(P, aQ)
        let a = 42u64;
        let lhs = miller_loop(&g1_mul(a), &g2::Point::GENERATOR);
        let rhs = miller_loop(&g1::Point::GENERATOR, &g2_mul(a));
        assert!(lhs.final_verify(&rhs));

        // e(aP, Q) != e(P, bQ) for a != b
        let other = miller_loop(&g1::Point::GENERATOR, &g2_mul(43));
        assert!(!lhs.final_verify(&other));
    }

    #[test]
    fn final_verify_agrees_with_comparing_two_final_exponentiations() {
        // the ratio form must not change the decision, on either answer
        let same = (
            miller_loop(&g1_mul(4), &g2_mul(6)),
            miller_loop(&g1_mul(6), &g2_mul(4)),
        );
        let different = (
            miller_loop(&g1_mul(4), &g2_mul(6)),
            miller_loop(&g1_mul(4), &g2_mul(7)),
        );
        for (a, b) in [same, different] {
            let two_exponentiations =
                final_exponentiation(a.inner()) == final_exponentiation(b.inner());
            assert_eq!(a.final_verify(&b), two_exponentiations);
        }
    }

    #[test]
    fn ml_result_multiplication_is_the_product_of_pairings() {
        // e(P1, Q) * e(P2, Q) == e(P1 + P2, Q)
        let q = g2_mul(6);
        let product = miller_loop(&g1_mul(4), &q).mul(&miller_loop(&g1_mul(7), &q));
        let sum = miller_loop(&g1_mul(11), &q);
        assert!(product.final_verify(&sum));

        // and the classic pairing check: e(-P, Q) * e(P, Q) == 1
        let neg = miller_loop(&-&g1_mul(4), &q).mul(&miller_loop(&g1_mul(4), &q));
        let one = MlResult::from_fp12(Fp12::ONE);
        assert!(neg.final_verify(&one));
    }
}

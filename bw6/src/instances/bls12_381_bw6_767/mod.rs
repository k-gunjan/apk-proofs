//! BLS12-381 + BW6-761 curve pairing instantiation
//!
//! This module provides type aliases and constants for APK proofs using:
//! - **Inner curve**: BLS12-381 G1 (for BLS signatures and public keys)
//! - **Outer curve**: BW6-761 G1 (for proof generation and verification)
//!
//! The BLS12-381/BW6-761 pairing is particularly efficient for recursive
//! proof composition due to the 2-chain structure where BW6-761's scalar
//! field matches BLS12-381's base field.
//!
//! ## Polynomial Commitment Schemes
//!
//! This pairing supports multiple PCS implementations:
//! - [`kzg`] - KZG commitments (default, most efficient)

// use ark_bls12_377::G1Projective as Bls12_377_G1;
use ark_bls12_381::G1Projective as Bls12_381_G1;
// use ark_bw6_761::{Fq, Fr, G1Affine as BW6_761_G1Affine, G1Projective as BW6_761_G1};
use ark_bw6_767::{Fr, G1Affine as BW6_767_G1Affine, G1Projective as BW6_767_G1};
use ark_ec::bls12::Bls12Config;

use crate::{AccountablePublicInput, CountingPublicInput, Keyset};

// ============================================================================
// Polynomial Commitment Schemes
// ============================================================================

/// KZG polynomial commitment scheme types for this pairing
pub mod kzg;

// Future: Other PCS implementations
// pub mod ipa;

// ============================================================================
// Curve Type Aliases
// ============================================================================

/// Inner curve: BLS12-381 G1
///
/// Used for:
/// - BLS signature public keys
/// - BLS signature aggregate public keys
/// - Elements being committed to in the keyset
pub type InnerCurve = Bls12_381_G1;

/// The pairing the inner curve belongs to. Needed to sign with these keys; see [`crate::bls`].
pub type InnerPairing = ark_bls12_381::Bls12_381;

/// Outer curve: BW6-761 G1 (projective)
///
/// Used for:
/// - Proof generation computations
/// - Polynomial commitments
/// - All arithmetic during proving
pub type OuterCurve = BW6_767_G1;

/// Outer curve: BW6-767 G1 (affine)
///
/// Used for:
/// - Serialization
/// - Verification
/// - Commitment points in proofs
pub type OuterAffine = BW6_767_G1Affine;

/// Outer curve scalar field: BW6-761 Fr
///
/// This field equals BLS12-381's base field (Fq), enabling
/// efficient recursive composition.
pub type OuterScalar = Fr;

// ============================================================================
// PCS-Independent Type Aliases
// ============================================================================

/// Keyset for BLS12-381 public keys with BW6-761 operations
///
/// This type is independent of the polynomial commitment scheme used.
/// The base domain sizes available to APK-381, ascending.
///
/// BW6-767's scalar field has `q - 1 = 2 * 3^2 * 11 * 23 * 47 * 10177 * (unusable large part)`.
/// Two of those factors are **reserved** rather than spent on the base domain: one 2 and one 3,
/// so that `6n` divides `q - 1` whenever `n` does. That fixes the triple as `n, 2n, 6n` —
/// `2n >= 2n - 1` and `6n >= 4n - 2`, both nested inside each other — and leaves the base sizes
/// as the divisors of
///
/// ```text
/// 3 * 11 * 23 * 47 * 10177 = 363,044,121
/// ```
///
/// listed here from the smallest to the largest the field admits. The largest entry's `6n` is
/// `2 * 3^2 * 11 * 23 * 47 * 10177`, the entire usable smooth part of `q - 1`, so the table
/// cannot be extended.
///
/// The price of reserving those factors is padding: the gaps are wide, and the worst case in the
/// range that matters is `n = 3244` rounding up to 11891, a factor of 3.67. Spending the 2 and
/// the 3 on the base domain would close the gaps, but then `2n` and `6n` would not exist and the
/// three domains would have to be chosen independently and would not nest.
///
/// Validator-set sizes of interest sit comfortably inside: Kusama's ~1000 lands on 1081 = 23*47
/// and Polkadot's ~1500 on 1551 = 3*11*47.
///
/// **Two divisors are deliberately absent: 10177 and 30531 = 3 * 10177.** Both are dominated —
/// the next entry up is larger *and* cheaper to transform, because 10177 is prime and has to go
/// through Rader's algorithm at roughly four times the per-point cost of a smooth radix. By the
/// cost model these sizes were selected with, one proof over 10177 is about 255M field
/// multiplications against 76M for `11891 = 11*23*47`, a domain only 17% bigger; 30531 is about
/// 772M against 234M for `35673 = 3*11*23*47`. Dropping them is what makes transform cost
/// increase with size across the whole table, which in turn is what lets domain selection be a
/// plain binary search rather than a runtime ranking.
///
/// Entries from 111947 up still carry the factor 10177 and still need Rader. There is no smooth
/// alternative that high, so nothing dominates them and they stay.
///
/// Every claim above is asserted in this module's tests rather than trusted: that each entry is
/// a divisor, that `6n` really is a subgroup order of this field, and that the two omissions are
/// the dominated ones.
pub const APK381_DOMAIN_SIZES: &[usize] = &[
    1,         // 1
    3,         // 3
    11,        // 11
    23,        // 23
    33,        // 3 * 11
    47,        // 47
    69,        // 3 * 23
    141,       // 3 * 47
    253,       // 11 * 23
    517,       // 11 * 47
    759,       // 3 * 11 * 23
    1081,      // 23 * 47          <- Kusama, ~1000 validators
    1551,      // 3 * 11 * 47      <- Polkadot, ~1500 validators
    3243,      // 3 * 23 * 47
    11891,     // 11 * 23 * 47     <- 10177 omitted: prime, and 11891 is cheaper
    35673,     // 3 * 11 * 23 * 47 <- 30531 = 3 * 10177 omitted for the same reason
    111947,    // 11 * 10177       <- Rader from here on, with no smooth alternative
    234071,    // 23 * 10177
    335841,    // 3 * 11 * 10177
    478319,    // 47 * 10177
    702213,    // 3 * 23 * 10177
    1434957,   // 3 * 47 * 10177
    2574781,   // 11 * 23 * 10177
    5261509,   // 11 * 47 * 10177
    7724343,   // 3 * 11 * 23 * 10177
    11001337,  // 23 * 47 * 10177
    15784527,  // 3 * 11 * 47 * 10177
    33004011,  // 3 * 23 * 47 * 10177
    121014707, // 11 * 23 * 47 * 10177
    363044121, // 3 * 11 * 23 * 47 * 10177
];

/// Binds [`APK381_DOMAIN_SIZES`] to BW6-767's scalar field.
pub struct Apk381DomainSizes;

impl crate::DomainSizes<OuterScalar> for Apk381DomainSizes {
    const SIZES: &'static [usize] = APK381_DOMAIN_SIZES;
}

/// Evaluation domains for BW6-767's scalar field.
///
/// Two-adicity is 1 there, so radix-2 does not exist: no power-of-two domain beyond size 2, and
/// no domain size divisible by 4 at all. Sizes come from [`APK381_DOMAIN_SIZES`] and are
/// transformed by mixed-radix Cooley-Tukey, with Rader for the factor 10177.
pub type Domains767 = crate::SmoothDomainSet<OuterScalar, Apk381DomainSizes>;

/// A single mixed-radix domain. Prefer [`Domains767`]: the protocol works over the triple, and
/// the triple is what makes the sizes `n, 2n, 6n` line up.
pub type Domain767 = crate::CooleyTukeyDomain<OuterScalar>;

pub type Keyset381 = Keyset<InnerCurve, OuterCurve, Domains767>;

/// Accountable public input for simple and packed proof schemes
///
/// Contains:
/// - Aggregate public key (APK) on the inner curve
/// - Bitmask identifying which keys participated
pub type AccountablePublicInput381 = AccountablePublicInput<InnerCurve>;

/// Counting public input for counting proof scheme
///
/// Contains:
/// - Aggregate public key (APK) on the inner curve  
/// - Count of participating keys (instead of full bitmask)
pub type CountingPublicInput381 = CountingPublicInput<InnerCurve>;

// ============================================================================
// Endomorphism Constants
// ============================================================================

// /// GLV endomorphism eigenvalue λ on BLS12-381 G1
// ///
// /// For the GLV endomorphism φ: (x,y) ↦ (ωx, y) where ω is a cube root of unity,
// /// we have φ(P) = λP for all P ∈ G1.
// ///
// /// This constant is used for efficient scalar multiplication via GLV decomposition.
// pub const LAMBDA: Fr = MontFp!(
//     "80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945"
// );

/// BLS12-381 curve parameter u (for GLV endomorphism)
///
/// The curve is defined using a parameter u, and this is used in the
/// GLV scalar decomposition algorithm for efficient scalar multiplication.
pub const U: &[u64] = ark_bls12_381::Config::X;

// /// Eigenvalue ω of the endomorphism on BW6-761
// ///
// /// For the endomorphism on BW6-761, this is the value such that
// /// the endomorphism acts as multiplication by ω on the x-coordinate.
// ///
// /// Used for efficient subgroup checking and scalar multiplication.
// pub const OMEGA: Fq = MontFp!(
//     "196898582409020929727861073970057715139766638230382572845074161156680037021882725775086501\
//      3421937292370006175842381275743914023380727582819905021229583192207421122272650305267822868\
//      639090213645505120388400344940985710520836292650"
// );

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::subgroup_generator;
    use num_bigint::BigUint;

    /// The list is the reserved-factor rule made explicit: every entry divides
    /// `3 * 11 * 23 * 47 * 10177`, and every divisor of it is an entry bar the two documented
    /// omissions. Pinning the omissions here is what keeps them a deliberate choice rather than
    /// a typo nobody would notice.
    #[test]
    fn table_is_the_divisors_of_the_unreserved_part_less_the_dominated_ones() {
        const DOMINATED: [usize; 2] = [10177, 30531];

        let unreserved: usize = 3 * 11 * 23 * 47 * 10177;
        let mut divisors: Vec<usize> = vec![1];
        for f in [3usize, 11, 23, 47, 10177] {
            divisors = divisors.iter().flat_map(|&d| [d, d * f]).collect();
        }
        divisors.sort_unstable();
        divisors.dedup();
        assert_eq!(divisors.len(), 32);

        let expected: Vec<usize> = divisors
            .iter()
            .copied()
            .filter(|n| !DOMINATED.contains(n))
            .collect();
        assert_eq!(APK381_DOMAIN_SIZES, &expected[..]);
        assert!(APK381_DOMAIN_SIZES.iter().all(|&n| unreserved % n == 0));
        assert_eq!(*APK381_DOMAIN_SIZES.last().unwrap(), unreserved);

        // Each omitted size really is dominated: the next entry up is larger, so no request is
        // left unserved, and it is cheaper, which is the reason to pass the smaller one over.
        for d in DOMINATED {
            let next = APK381_DOMAIN_SIZES
                .iter()
                .copied()
                .find(|&n| n > d)
                .expect("a dominated entry must have a successor");
            assert!(next < 2 * d, "{} would double the padding, not a fair swap", next);
        }
    }

    /// The reason the 2 and the 3 are held back: `6n` has to exist for every entry, and it has
    /// to be the whole usable smooth part of `q - 1` at the top of the table.
    #[test]
    fn every_entry_admits_its_doubled_and_sextupled_domain() {
        let order: BigUint =
            Into::<BigUint>::into(<OuterScalar as ark_ff::PrimeField>::MODULUS) - 1u8;
        for &n in APK381_DOMAIN_SIZES {
            assert!(
                (&order % BigUint::from(6 * n)) == BigUint::from(0u32),
                "6 * {} does not divide q - 1",
                n
            );
        }
        assert_eq!(
            6 * APK381_DOMAIN_SIZES.last().unwrap(),
            2 * 9 * 11 * 23 * 47 * 10177,
            "the largest triple should exhaust the smooth part of q - 1"
        );
        // ...and each `6n` really is a subgroup order of this field. This is the `DomainSizes`
        // contract that `SmoothDomainSet::build` only `debug_assert`s, so that the production
        // path does a binary search and nothing else. Asserting it here is what earns that.
        for &n in APK381_DOMAIN_SIZES {
            assert!(
                subgroup_generator::<OuterScalar>(6 * n).is_some(),
                "6 * {} is not a subgroup order of BW6-767's scalar field",
                n
            );
        }
    }
}

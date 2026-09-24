//! Succinct proofs of a BLS public key being an aggregate key of a subset of signers given a commitment to the set of all signers' keys
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{FftField, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::Zero;
use w3f_pcs::pcs::commitment::WrappedAffine;

pub use bitmask::Bitmask;
pub use keyset::{Keyset, KeysetCommitment};

use crate::piop::affine_addition::{PartialSumsAndBitmaskCommitments, PartialSumsCommitments};
use crate::piop::basic::AffineAdditionEvaluationsWithoutBitmask;
use crate::piop::bitmask_packing::{
    BitmaskPackingCommitments, SuccinctAccountableRegisterEvaluations,
};
use crate::piop::counting::{CountingCommitments, CountingEvaluations};
use crate::piop::RegisterEvaluations;

pub use self::prover::*;
pub use self::verifier::*;

pub mod endo;
pub mod instances;
mod prover;
pub mod utils;
mod verifier;

pub mod bls;
pub mod config;
pub mod domain;
pub use config::{
    AccountablePublicInputOf, Apk, Apk377, Apk381, ApkConfig, Bls12_377Config, Bls12_381Config,
    CountingProofOf, CountingPublicInputOf, KeysetCommitmentOf, KeysetOf, PackedProofOf,
    PcsParamsOf, ProverOf, ScalarOf, SimpleProofOf, VerifierOf,
};
pub use domain::{
    CooleyTukeyDomain, DomainError, DomainSet, DomainSizes, DomainTriple, FftDomain,
    NaiveDomain, Radix2Domain, Radix2DomainSet, SmoothDomainSet, SupportsPackedScheme,
};

mod transcript;

pub mod domains;
mod fsrng;
mod piop;

mod bitmask;
mod keyset;
pub mod setup;
/// Test fixtures, including insecure SRS generation. Compiled only for this crate's own tests
/// and under the `test-utils` feature, never into a production build.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_helpers;

/// Trait to extract the underlying curve point from a type e.g. commitment and get it back.
pub trait CommitmentExt<F: PrimeField> {
    type Affine: AffineRepr<ScalarField = F>;

    /// Extract the underlying affine point
    fn to_affine(&self) -> Self::Affine;

    /// Construct the commitment from an affine point
    fn from_affine(p: Self::Affine) -> Self;
}

/// Commitment schemes that commit to a single curve point represent it as [`WrappedAffine`];
/// this is how the rest of the crate gets the point back out without naming a scheme.
impl<C: CurveGroup> CommitmentExt<C::ScalarField> for WrappedAffine<C> {
    type Affine = C::Affine;

    fn to_affine(&self) -> Self::Affine {
        self.0
    }

    fn from_affine(p: Self::Affine) -> Self {
        WrappedAffine(p)
    }
}

// TODO: 1. From trait?
// TODO: 2. remove refs/clones
pub trait PublicInput<C: CurveGroup>: CanonicalSerialize + CanonicalDeserialize {
    fn new(apk: &C::Affine, bitmask: &Bitmask) -> Self;
}

// Used in 'basic' and 'packed' schemes
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct AccountablePublicInput<C: CurveGroup> {
    pub apk: C::Affine,
    pub bitmask: Bitmask,
}

impl<C: CurveGroup> PublicInput<C> for AccountablePublicInput<C> {
    fn new(apk: &C::Affine, bitmask: &Bitmask) -> Self {
        AccountablePublicInput {
            apk: apk.clone(),
            bitmask: bitmask.clone(),
        }
    }
}

// Used in 'counting' scheme
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct CountingPublicInput<C: CurveGroup> {
    pub apk: C::Affine,
    pub count: usize,
}

impl<C: CurveGroup> PublicInput<C> for CountingPublicInput<C> {
    fn new(apk: &C::Affine, bitmask: &Bitmask) -> Self {
        CountingPublicInput {
            apk: apk.clone(),
            count: bitmask.count_ones(),
        }
    }
}

/// Generic proof structure for APK proofs
///
/// Generic over:
/// - `F`: Field type (scalar field of the outer curve)
/// - `E`: Register evaluations type
/// - `C`: First round register commitments type
/// - `AC`: Second round additional commitments type (for packed scheme)
/// - `Comm`: Commitment type (e.g., `WrappedAffine`)
/// - `OProof`: Opening proof type (PCS-specific)
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<F, E, C, AC, Comm, OProof>
where
    F: FftField,
    E: RegisterEvaluations<F>,
    C: CanonicalSerialize + CanonicalDeserialize,
    AC: CanonicalSerialize + CanonicalDeserialize,
    Comm: CanonicalSerialize + CanonicalDeserialize + Clone,
    OProof: CanonicalSerialize + CanonicalDeserialize + Clone,
{
    /// First round register commitments
    pub register_commitments: C,
    /// Second round commitments (used in "packed" scheme after bitmask aggregation challenge)
    pub additional_commitments: AC,
    /// Quotient polynomial commitment (after receiving φ challenge)
    pub q_comm: Comm,
    /// Register polynomial evaluations at ζ
    pub register_evaluations: E,
    /// Quotient polynomial evaluation at ζ
    pub q_zeta: F,
    /// Linearization polynomial evaluation at ζω
    pub r_zeta_omega: F,
    /// Opening proof for aggregated polynomial at ζ
    pub w_at_zeta_proof: OProof,
    /// Opening proof for linearization polynomial at ζω
    pub r_at_zeta_omega_proof: OProof,
}

/// Simple proof type (basic scheme without bitmask packing)
pub type SimpleProof<F, G, Comm, OProof> = Proof<
    F,
    AffineAdditionEvaluationsWithoutBitmask<F>,
    PartialSumsCommitments<G>,
    (),
    Comm,
    OProof,
>;

/// Packed proof type (with bitmask packing for succinctness)
pub type PackedProof<F, G, Comm, OProof> = Proof<
    F,
    SuccinctAccountableRegisterEvaluations<F>,
    PartialSumsAndBitmaskCommitments<G>,
    BitmaskPackingCommitments<G>,
    Comm,
    OProof,
>;
/// Counting proof type (only proves count, not individual bits)
pub type CountingProof<F, G, Comm, OProof> =
    Proof<F, CountingEvaluations<F>, CountingCommitments<G>, (), Comm, OProof>;

/// `(0, sqrt(b))`: a point on the curve `y^2 = x^3 + b` but outside its prime-order subgroup.
///
/// On a curve with `a = 0` any point with `x = 0` is a flex point, so it has order 3; as long as
/// 3 does not divide the subgroup order, it cannot lie in the subgroup. Of the two square roots
/// the numerically smaller is taken, so the point is the same on every machine: `(0, 1)` on
/// BLS12-377 (`b = 1`) and `(0, 2)` on BLS12-381 (`b = 4`).
///
/// Panics if `a != 0` or `b` is not a square, i.e. on curves this construction does not fit.
/// That the result really is on the curve and outside the subgroup is asserted in tests per
/// curve, not here, to keep a subgroup check off the prover's and verifier's paths.
pub fn point_in_g1_complement<P: SWCurveConfig>() -> Affine<P> {
    assert!(
        P::COEFF_A.is_zero(),
        "(0, sqrt(b)) needs a curve with a = 0"
    );
    let y = P::COEFF_B
        .sqrt()
        .expect("b is not a square: (0, sqrt(b)) is not on this curve");
    let y = core::cmp::min(y, -y);
    Affine::<P>::new_unchecked(P::BaseField::zero(), y)
}

/// Inner curves that can carry the affine-addition accumulator.
///
/// The accumulator starts at [`AccumulatorSeed::accumulator_seed`], a point `h` on the curve but
/// **outside** the prime-order subgroup G1 the public keys live in. That is what keeps the
/// incomplete addition formulas sound: `h + S` for any sum `S` of G1 points is never `±pk` for a
/// `pk` in G1, so the prover can never reach the doubling case — where both addition
/// constraints vanish for *any* next accumulator value — and never reaches the identity, which
/// has no affine form. A seed inside G1 (the generator, say) gives both away to anyone able to
/// register a key.
///
/// Every [`ApkConfig::InnerCurve`] must implement this; see `crate::instances`.
pub trait AccumulatorSeed: CurveGroup {
    fn accumulator_seed() -> Self::Affine;
}

// TODO: switch to better hash to curve when available
pub fn hash_to_curve<G: CurveGroup>(message: &[u8]) -> G {
    use ark_std::rand::SeedableRng;
    use blake2::Digest;

    let seed = blake2::Blake2s::digest(message);
    let rng = &mut rand::rngs::StdRng::from_seed(seed.into());
    G::rand(rng)
}

#[cfg(test)]
mod tests {
    use crate::test_helpers;

    use super::*;

    #[test]
    fn h_is_not_in_g1_bw6_761() {
        let h = point_in_g1_complement::<ark_bw6_761::g1::Config>();
        assert!(h.is_on_curve());
        assert!(!h.is_in_correct_subgroup_assuming_on_curve());
    }

    #[test]
    fn h_is_not_in_g1_bls12_377() {
        let h = point_in_g1_complement::<ark_bls12_377::g1::Config>();
        assert!(h.is_on_curve());
        assert!(!h.is_in_correct_subgroup_assuming_on_curve());
    }

    /// `(0, 1)` is not even on BLS12-381 (`b = 4`); the construction has to land on `(0, 2)`.
    #[test]
    fn h_is_not_in_g1_bls12_381() {
        let h = point_in_g1_complement::<ark_bls12_381::g1::Config>();
        assert_eq!(h.y().unwrap(), ark_bls12_381::Fq::from(2u8));
        assert!(h.is_on_curve());
        assert!(!h.is_in_correct_subgroup_assuming_on_curve());
    }

    #[test]
    fn test_simple_scheme() {
        test_helpers::test_simple_scheme(255);
    }

    #[test]
    fn test_packed_scheme() {
        test_helpers::test_packed_scheme(255);
    }

    #[test]
    fn test_counting_scheme() {
        test_helpers::test_counting_scheme(255);
    }

    // APK-381. 516 keys need a domain of at least 517, which is 11 * 47 exactly; the expanded
    // domains are then 1034 and 3102. None is a power of two, and none is a multiple of 4.
    //
    // 517 rather than the smaller 253 on purpose: ark-poly switches polynomial division to an
    // FFT-based algorithm once the divisor's degree reaches 256, which this field cannot
    // support. Every 381 test used to sit just under that line, so the prover panicked for
    // every real validator set while the suite stayed green.
    #[test]
    fn test_simple_scheme_381() {
        test_helpers::test_simple_scheme_381(516);
    }

    #[test]
    fn test_counting_scheme_381() {
        test_helpers::test_counting_scheme_381(516);
    }

    #[test]
    fn test_rejects_tampering_377() {
        test_helpers::test_rejects_tampering_377(255);
    }

    #[test]
    fn test_rejects_tampering_381() {
        test_helpers::test_rejects_tampering_381(516);
    }

    #[test]
    fn test_rejects_bad_domain_size_377() {
        test_helpers::test_rejects_bad_domain_size_377(255);
    }

    #[test]
    fn test_rejects_bad_domain_size_381() {
        test_helpers::test_rejects_bad_domain_size_381(252);
    }

    /// An SRS sized for a smaller keyset must fail early and say so.
    #[test]
    fn test_undersized_srs_is_reported_at_prover_construction() {
        test_helpers::test_undersized_srs_is_reported_at_prover_construction();
    }

    /// One function body, both curves.
    #[test]
    fn test_config_driven_api() {
        test_helpers::test_config_driven_api();
    }

    /// CI gate: generic code must not name a concrete curve or a radix-2 domain. Generic code
    /// rots back into concrete code quietly, and a single reintroduced `Radix2EvaluationDomain`
    /// would break APK-381 only at runtime, on a curve whose tests are the slowest to run.
    #[test]
    fn generic_code_names_no_concrete_curve_or_domain() {
        use std::path::Path;

        fn visit(dir: &Path, findings: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    visit(&path, findings);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let rel = path
                    .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                    .unwrap_or(&path);
                let rel = rel.to_string_lossy().replace('\\', "/");
                // Where naming a concrete curve or domain is the entire point.
                if rel.contains("src/instances/")
                    || rel.contains("src/domain/radix2.rs")
                    || rel.ends_with("src/test_helpers.rs")
                {
                    continue;
                }
                let src = std::fs::read_to_string(&path).unwrap();
                // Test modules legitimately pick concrete curves to test against.
                let production = match src.find("#[cfg(test)]") {
                    Some(i) => &src[..i],
                    None => &src[..],
                };
                // Comments may name curves freely; the point is that no *code* does.
                let production: String = production
                    .lines()
                    .map(|l| l.split("//").next().unwrap_or(""))
                    .collect::<Vec<_>>()
                    .join("\n");
                for needle in [
                    "Radix2EvaluationDomain",
                    "ark_bw6_761",
                    "ark_bw6_767",
                    "ark_bls12_377",
                    "ark_bls12_381",
                    "log_size_of_group",
                    "TWO_ADICITY",
                ] {
                    if production.contains(needle) {
                        findings.push(format!("{} names {}", rel, needle));
                    }
                }
            }
        }

        let mut findings = Vec::new();
        visit(
            Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src")),
            &mut findings,
        );
        assert!(
            findings.is_empty(),
            "generic code is not generic:\n  {}",
            findings.join("\n  ")
        );
    }
}

//! Succinct proofs of a BLS public key being an aggregate key of a subset of signers given a commitment to the set of all signers' keys
use ark_ec::pairing::Pairing;
use ark_std::{One, Zero};
use ark_bw6_761::{Fq, Fr, BW6_761};
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{FftField, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fflonk::pcs::kzg::commitment::KzgCommitment;
use fflonk::pcs::kzg::KZG;

pub use bitmask::Bitmask;
pub use keyset::{Keyset, KeysetCommitment};

use crate::piop::RegisterEvaluations;
use crate::piop::affine_addition::{PartialSumsAndBitmaskCommitments, PartialSumsCommitments};
use crate::piop::basic::AffineAdditionEvaluationsWithoutBitmask;
use crate::piop::bitmask_packing::{BitmaskPackingCommitments, SuccinctAccountableRegisterEvaluations};
use crate::piop::counting::{CountingCommitments, CountingEvaluations};

pub use self::prover::*;
pub use self::verifier::*;

mod prover;
mod verifier;
pub mod endo;
pub mod utils;

pub mod bls;

mod transcript;

mod fsrng;
pub mod domains;
mod piop;

pub mod setup;
mod bitmask;
mod keyset;
pub mod test_helpers; //TODO: cfgtest

/// Trait to extract the underlying curve point from a type e.g. commitment and get it back.
pub trait CommitmentExt<F: PrimeField> {
    type Affine: AffineRepr<ScalarField = F>;
    
    /// Extract the underlying affine point
    fn to_affine(&self) -> Self::Affine;

    /// Construct the commitment from an affine point
    fn from_affine(p: Self::Affine) ->Self;
}

impl<E: Pairing> CommitmentExt<E::ScalarField> for KzgCommitment<E> {
    type Affine = E::G1Affine;
    
    fn to_affine(&self) -> Self::Affine {
        self.0
    }

    fn from_affine(p: Self::Affine) ->Self {
        KzgCommitment(p)
    }
}

// TODO: 1. From trait?
// TODO: 2. remove refs/clones
pub trait PublicInput<C: CurveGroup> : CanonicalSerialize + CanonicalDeserialize {
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
/// - `Comm`: Commitment type (e.g., KzgCommitment)
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
pub type CountingProof<F, G, Comm, OProof> = Proof<
    F,
    CountingEvaluations<F>,
    CountingCommitments<G>,
    (),
    Comm,
    OProof,
>;

// Export oncrete type aliases
pub type KeysetBls377 = Keyset<ark_bls12_377::Bls12_377, BW6_761>;
pub type KeysetCommitmentBls377 = KeysetCommitment<Fr, KzgCommitment<BW6_761>>;

pub type SimpleProofBW6_761 = SimpleProof<
    Fr,
    ark_bw6_761::G1Affine,
    KzgCommitment<BW6_761>,
    ark_bw6_761::G1Affine,
>;

pub type PackedProofBW6_761 = PackedProof<
    Fr,
    ark_bw6_761::G1Affine,
    KzgCommitment<BW6_761>,
    ark_bw6_761::G1Affine,
>;

pub type CountingProofBW6_761 = CountingProof<
    Fr,
    ark_bw6_761::G1Affine,
    KzgCommitment<BW6_761>,
    ark_bw6_761::G1Affine,
>;

// const H_X: Fr = MontFp!("0");
// const H_Y: Fr = MontFp!("1");

pub fn point_in_g1_complement<P: SWCurveConfig>() -> Affine<P> {
    let h_x: P::BaseField = P::BaseField::zero();
    let h_y: P::BaseField = P::BaseField::one();

    Affine::<P>::new_unchecked(h_x, h_y)
}

// TODO: Generator + one should be in the group complement. better approach?
pub fn point_in_g1_complement_g<C: CurveGroup>() ->C
{
    let mut h = C::zero();
    let one = C::ScalarField::one();
    h += C::generator() * one;
    h
}

// TODO: switch to better hash to curve when available
pub fn hash_to_curve<G: CurveGroup>(message: &[u8]) -> G {
    use blake2::Digest;
    use ark_std::rand::SeedableRng;

    let seed = blake2::Blake2s::digest(message);
    let rng = &mut rand::rngs::StdRng::from_seed(seed.into());
    G::rand(rng)
}

#[cfg(test)]
mod tests {
    use crate::test_helpers;

    use super::*;

    #[test]
    fn h_is_not_in_g1_bw6() {
        let h = point_in_g1_complement::<ark_bw6_761::g1::Config>();
        assert!(h.is_on_curve());
        assert!(!h.is_in_correct_subgroup_assuming_on_curve());
    }

     #[test]
    fn h_is_not_in_g1_bls12() {
        let h = point_in_g1_complement::<ark_bls12_377::g1::Config>();
        assert!(h.is_on_curve());
        assert!(!h.is_in_correct_subgroup_assuming_on_curve());
    }

    #[test]
    fn test_simple_scheme() {
        test_helpers::test_simple_scheme(8);
    }


    #[test]
    fn test_packed_scheme() {
        test_helpers::test_packed_scheme(8);
    }

    #[test]
    fn test_counting_scheme() {
        test_helpers::test_counting_scheme(8);
    }
}
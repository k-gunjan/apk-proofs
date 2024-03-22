//! Succinct proofs of a BLS public key being an aggregate key of a subset of signers given a commitment to the set of all signers' keys
use ark_ec::bls12::Bls12Config;
use ark_ec::bls12::G1Affine;
pub use ark_ec::bw6::{BW6Config, TwistType, BW6};
use ark_ec::short_weierstrass::Projective;
use ark_ec::CurveConfig;
use ark_ec::CurveGroup;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fflonk::pcs::kzg::KZG;

pub use bitmask::Bitmask;
pub use keyset::{Keyset, KeysetCommitment};

use crate::piop::affine_addition::{PartialSumsAndBitmaskCommitments, PartialSumsCommitments};
use crate::piop::basic::AffineAdditionEvaluationsWithoutBitmask;
use crate::piop::bitmask_packing::{
    BitmaskPackingCommitments, SuccinctAccountableRegisterEvaluations,
};
use crate::piop::counting::{CountingCommitments, CountingEvaluations};
use crate::piop::{RegisterCommitments, RegisterEvaluations};
pub use ark_bw6_761::Config as BigCurveCongig;
mod bw6_761_config;
// pub use bw6_761_config::Config as BigCurveCongig;

pub use self::prover::*;
pub use self::verifier::*;
pub use ark_bls12_377::Config as Config377;
pub use ark_bw6_761::FrConfig as FrConfig761;
use ark_ff::{biginteger::BigInteger768 as BigInteger, BigInt};

pub mod endo;
mod prover;
pub mod utils;
mod verifier;

pub mod bls;

mod transcript;

pub mod domains;
mod fsrng;
mod piop;

mod bitmask;
mod keyset;
pub mod setup;
pub mod test_helpers; //TODO: cfgtest

// type NewKzgBw6 = KZG<BW6<BigCurveCongig>>;
type NewKzgBw6<Config> = KZG<BW6<Config>>;
pub type Fr<F> = <<F as BW6Config>::G1Config as CurveConfig>::ScalarField;
pub type G1Projective<P> = Projective<<P as Bls12Config>::G1Config>;

// TODO: 1. From trait?
// TODO: 2. remove refs/clones
pub trait PublicInput: CanonicalSerialize + CanonicalDeserialize {
    type Config: Bls12Config;
    fn new(apk: &G1Affine<Self::Config>, bitmask: &Bitmask) -> Self;
}

// Used in 'basic' and 'packed' schemes
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct AccountablePublicInput<ConfigBls12: Bls12Config> {
    pub apk: G1Affine<ConfigBls12>,
    pub bitmask: Bitmask,
}

impl<ConfigBls12: Bls12Config> PublicInput for AccountablePublicInput<ConfigBls12> {
    type Config = ConfigBls12;
    fn new(apk: &G1Affine<Self::Config>, bitmask: &Bitmask) -> Self {
        AccountablePublicInput {
            apk: apk.clone(),
            bitmask: bitmask.clone(),
        }
    }
}

// Used in 'counting' scheme
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct CountingPublicInput<ConfigBls12: Bls12Config> {
    pub apk: G1Affine<ConfigBls12>,
    pub count: usize,
}

impl<ConfigBls12: Bls12Config> PublicInput for CountingPublicInput<ConfigBls12> {
    type Config = ConfigBls12;
    fn new(apk: &G1Affine<Self::Config>, bitmask: &Bitmask) -> Self {
        CountingPublicInput {
            apk: apk.clone(),
            count: bitmask.count_ones(),
        }
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<
    E: RegisterEvaluations,
    C: RegisterCommitments,
    AC: RegisterCommitments,
    Config761: BW6Config,
> {
    register_commitments: C,
    // 2nd round commitments, used in "packed" scheme after get the bitmask aggregation challenge is received
    additional_commitments: AC,
    // Prover receives \phi, the constraint polynomials batching challenge, here
    q_comm: ark_ec::bw6::G1Affine<Config761>,
    // Prover receives \zeta, the evaluation point challenge, here
    register_evaluations: E,
    q_zeta: Fr<Config761>,
    r_zeta_omega: Fr<Config761>,
    // Prover receives \nu, the KZG opening batching challenge, here
    w_at_zeta_proof: ark_ec::bw6::G1Affine<Config761>,
    r_at_zeta_omega_proof: ark_ec::bw6::G1Affine<Config761>,
}

pub type SimpleProof<Config761> =
    Proof<AffineAdditionEvaluationsWithoutBitmask, PartialSumsCommitments, (), Config761>;
pub type PackedProof<Config761> = Proof<
    SuccinctAccountableRegisterEvaluations,
    PartialSumsAndBitmaskCommitments,
    BitmaskPackingCommitments,
    Config761,
>;
pub type CountingProof<Config761> = Proof<CountingEvaluations, CountingCommitments, (), Config761>;

use ark_std::One;
use ark_std::Zero;
fn point_in_g1_complement<C: Bls12Config>() -> G1Affine<C> {
    G1Affine::<C>::new_unchecked(
        <C as Bls12Config>::Fp::zero(),
        <C as Bls12Config>::Fp::one(),
    )
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
    fn h_is_not_in_g1() {
        let h = point_in_g1_complement::<Config377>();
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

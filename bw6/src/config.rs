//! Curve configurations.
//!
//! An APK proof is parameterised by four things that are not independent: an inner BLS12 curve
//! carrying the signatures, an outer BW6 curve the proof is computed over, a polynomial
//! commitment scheme on the outer curve, and an FFT strategy for the outer curve's scalar field.
//! Only a handful of combinations are coherent — the outer curve's scalar field has to be the
//! inner curve's base field, and the FFT strategy has to match that field's structure.
//!
//! [`ApkConfig`] bundles them, so choosing a curve is naming one type rather than four, and
//! combinations that do not make sense cannot be spelled.

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use w3f_pcs::pcs::PCS;

use crate::domain::DomainFactory;

/// The scalar field of a configuration's outer curve, which is also the base field of its inner
/// curve. All polynomial arithmetic happens here.
pub type ScalarOf<C> = <<C as ApkConfig>::OuterCurve as ark_ec::PrimeGroup>::ScalarField;

/// A coherent choice of curves, commitment scheme and FFT strategy.
pub trait ApkConfig: 'static + Sized {
    /// Distinguishes configurations in the Fiat-Shamir transcript.
    const NAME: &'static str;

    /// Where the BLS public keys live.
    type InnerCurve: CurveGroup;

    /// Where the proof is computed. Its scalar field is `InnerCurve`'s base field, which is what
    /// lets inner-curve coordinates be manipulated as native field elements.
    type OuterCurve: CurveGroup;

    /// Commitment scheme over the outer curve.
    type Pcs: PCS<ScalarOf<Self>>;

    /// Evaluation domains for the outer curve's scalar field. This is the component that cannot
    /// be shared between configurations: see [`crate::domain`].
    type Domain: DomainFactory<ScalarOf<Self>>;
}

/// The prover for a configuration.
pub type ProverOf<C> = crate::Prover<
    <C as ApkConfig>::InnerCurve,
    <C as ApkConfig>::OuterCurve,
    <C as ApkConfig>::Pcs,
    <C as ApkConfig>::Domain,
>;

/// The verifier for a configuration.
pub type VerifierOf<C> = crate::Verifier<
    <C as ApkConfig>::InnerCurve,
    <C as ApkConfig>::OuterCurve,
    <C as ApkConfig>::Pcs,
    <C as ApkConfig>::Domain,
>;

/// The keyset type for a configuration.
pub type KeysetOf<C> = crate::Keyset<
    <C as ApkConfig>::InnerCurve,
    <C as ApkConfig>::OuterCurve,
    <C as ApkConfig>::Domain,
>;

/// The keyset commitment type for a configuration.
pub type KeysetCommitmentOf<C> =
    crate::KeysetCommitment<ScalarOf<C>, <<C as ApkConfig>::Pcs as PCS<ScalarOf<C>>>::C>;

/// Generates commitment-scheme parameters big enough for `keyset_size` public keys.
///
/// The domain, not the caller, decides the realised size; see [`crate::setup`].
pub fn setup_for_keyset<C, R>(keyset_size: usize, rng: &mut R) -> <C::Pcs as PCS<ScalarOf<C>>>::Params
where
    C: ApkConfig,
    R: rand::Rng,
    ScalarOf<C>: PrimeField,
{
    crate::setup::generate_for_keyset::<R, ScalarOf<C>, C::Pcs, C::Domain>(keyset_size, rng)
}

/// BLS12-377 signatures, proofs over BW6-761, KZG commitments, radix-2 domains.
///
/// BW6-761's scalar field has two-adicity 46, so power-of-two domains exist for every size the
/// prover could want and arkworks' radix-2 machinery applies unchanged.
pub struct Bls12_377Config;

impl ApkConfig for Bls12_377Config {
    const NAME: &'static str = "apk-bls12-377-bw6-761";
    type InnerCurve = crate::instances::bls12_377_bw6_761::InnerCurve;
    type OuterCurve = crate::instances::bls12_377_bw6_761::OuterCurve;
    type Pcs = crate::instances::bls12_377_bw6_761::kzg::PcsKzgBw6_761;
    type Domain = crate::instances::bls12_377_bw6_761::Domain761;
}

/// BLS12-381 signatures, proofs over BW6-767, KZG commitments, mixed-radix domains.
///
/// BW6-767's scalar field has two-adicity **1**. No power-of-two domain beyond size 2 exists
/// there and no domain size is divisible by 4, so sizes are divisors of
/// `2 * 3^2 * 11 * 23 * 47 * 10177` and are transformed by Cooley-Tukey with Rader for the
/// large factor.
///
/// The `packed` scheme is unavailable here — it needs `256 | n`. Asking for it is a compile
/// error; see [`crate::SupportsPackedScheme`].
pub struct Bls12_381Config;

impl ApkConfig for Bls12_381Config {
    const NAME: &'static str = "apk-bls12-381-bw6-767";
    type InnerCurve = crate::instances::bls12_381_bw6_767::InnerCurve;
    type OuterCurve = crate::instances::bls12_381_bw6_767::OuterCurve;
    type Pcs = crate::instances::bls12_381_bw6_767::kzg::Pcs;
    type Domain = crate::instances::bls12_381_bw6_767::Domain767;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::FftDomain;
    use ark_std::{test_rng, UniformRand};

    /// The API the crate is meant to be used through: name a curve, get a proof.
    /// The same four lines run on either configuration.
    #[test]
    fn apk_facade_roundtrips_on_both_configurations() {
        fn roundtrip<C: ApkConfig>(params: PcsParamsOf<C>, n: usize) -> bool
        where
            ScalarOf<C>: From<<C::InnerCurve as CurveGroup>::BaseField> + ark_ff::FftField,
            <C::Pcs as PCS<ScalarOf<C>>>::C: crate::CommitmentExt<
                    ScalarOf<C>,
                    Affine = <C::OuterCurve as CurveGroup>::Affine,
                > + Clone,
            PcsParamsOf<C>: Clone,
        {
            let rng = &mut test_rng();
            let pks: Vec<C::InnerCurve> = (0..n).map(|_| C::InnerCurve::rand(rng)).collect();

            let (keyset, commitment) = Apk::<C>::commit_keyset(&params, pks);
            let bitmask = crate::Bitmask::from_bits(&vec![true; n]);
            let (proof, public_input) = Apk::<C>::prove(&params, keyset, &commitment, bitmask);
            Apk::<C>::verify(&params, commitment, &public_input, &proof).unwrap()
        }

        assert!(roundtrip::<Bls12_377Config>(
            setup_for_keyset::<Bls12_377Config, _>(255, &mut test_rng()),
            255
        ));

        use crate::instances::bls12_381_bw6_767::Domain767;
        assert!(roundtrip::<Bls12_381Config>(
            crate::instances::bls12_381_bw6_767::kzg::generate_urs(
                3 * Domain767::create_domain(253).size() - 3,
                &mut test_rng(),
            ),
            252
        ));
    }

    /// Selecting a curve is naming one type, and the FFT strategy follows from it rather than
    /// being chosen by the caller.
    #[test]
    fn a_config_determines_its_domain_strategy() {
        // Radix-2: powers of two.
        let d377 = <Bls12_377Config as ApkConfig>::Domain::create_domain(200);
        assert_eq!(d377.size(), 256);

        // Mixed-radix: divisors of the smooth part of q - 1, and 256 is not one of them.
        let d381 = <Bls12_381Config as ApkConfig>::Domain::create_domain(200);
        assert_eq!(d381.size(), 207); // 3^2 * 23
        assert_ne!(d381.size() % 4, 0, "no BW6-767 domain is a multiple of 4");
    }

    #[test]
    fn configs_are_named_distinctly() {
        assert_ne!(Bls12_377Config::NAME, Bls12_381Config::NAME);
    }
}

/// Convenience aliases for a configuration's proof and public-input types.
pub type SimpleProofOf<C> = crate::SimpleProof<
    ScalarOf<C>,
    <<C as ApkConfig>::OuterCurve as CurveGroup>::Affine,
    <<C as ApkConfig>::Pcs as PCS<ScalarOf<C>>>::C,
    <<C as ApkConfig>::Pcs as PCS<ScalarOf<C>>>::Proof,
>;
pub type AccountablePublicInputOf<C> =
    crate::AccountablePublicInput<<C as ApkConfig>::InnerCurve>;
pub type PcsParamsOf<C> = <<C as ApkConfig>::Pcs as PCS<ScalarOf<C>>>::Params;

/// The APK proof system for a configuration.
///
/// The entry point when you want the protocol rather than its parts: `Apk::<Bls12_381Config>`
/// picks the curves, the commitment scheme and the FFT strategy together. Use
/// [`ProverOf`]/[`VerifierOf`] directly when you need to reuse a prover across many proofs.
pub struct Apk<C: ApkConfig>(core::marker::PhantomData<C>);

impl<C: ApkConfig> Apk<C>
where
    ScalarOf<C>: From<<C::InnerCurve as CurveGroup>::BaseField> + ark_ff::FftField,
    <C::Pcs as PCS<ScalarOf<C>>>::C:
        crate::CommitmentExt<ScalarOf<C>, Affine = <C::OuterCurve as CurveGroup>::Affine> + Clone,
    PcsParamsOf<C>: Clone,
{
    /// Interpolates and commits to a signer set.
    ///
    /// The domain size follows from `pks.len()`; the commitment records it so the verifier
    /// reconstructs the same one.
    pub fn commit_keyset(
        params: &PcsParamsOf<C>,
        pks: Vec<C::InnerCurve>,
    ) -> (KeysetOf<C>, KeysetCommitmentOf<C>) {
        use w3f_pcs::pcs::PcsParams;
        let keyset = KeysetOf::<C>::new(pks);
        let commitment = keyset.commit::<C::Pcs>(&params.ck());
        (keyset, commitment)
    }

    /// Proves that `bitmask` selects the signers whose aggregate key the returned public input
    /// names.
    pub fn prove(
        params: &PcsParamsOf<C>,
        keyset: KeysetOf<C>,
        commitment: &KeysetCommitmentOf<C>,
        bitmask: crate::Bitmask,
    ) -> (SimpleProofOf<C>, AccountablePublicInputOf<C>) {
        let prover = ProverOf::<C>::new(
            keyset,
            commitment,
            params.clone(),
            merlin::Transcript::new(b"apk_proof"),
        );
        prover.prove_simple(bitmask)
    }

    /// Checks a proof against a claimed aggregate key and bitmask.
    ///
    /// Returns `false` for any invalid proof rather than panicking, and errors rather than
    /// panicking when the commitment names a domain this configuration cannot build.
    pub fn verify(
        params: &PcsParamsOf<C>,
        commitment: KeysetCommitmentOf<C>,
        public_input: &AccountablePublicInputOf<C>,
        proof: &SimpleProofOf<C>,
    ) -> Result<bool, crate::DomainError> {
        use w3f_pcs::pcs::PcsParams;
        let verifier = VerifierOf::<C>::try_new(
            params.raw_vk(),
            commitment,
            merlin::Transcript::new(b"apk_proof"),
        )?;
        Ok(verifier.verify_simple(public_input, proof))
    }
}

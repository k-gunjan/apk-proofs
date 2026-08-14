use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{One, test_rng, Zero};
use ark_std::{end_timer, start_timer};
use ark_std::rand::Rng;
use w3f_pcs::pcs::{PCS, PcsParams};
use merlin::Transcript;
use crate::instances::bls12_377_bw6_761::kzg::PcsKzgBw6_761 as Pcs;
use crate::{DomainFactory, FftDomain};
use crate::{Bitmask, CommitmentExt, Keyset, CountingProof, PackedProof, SimpleProof, Prover, PublicInput, setup, Verifier};

pub(crate) fn _random_bits<R: Rng>(n: usize, density: f64, rng: &mut R) -> Vec<bool> {
    (0..n).map(|_| rng.gen_bool(density)).collect()
}

pub(crate) fn _random_bitmask<R: Rng, C: CurveGroup>(n: usize, rng: &mut R) -> Vec<C::ScalarField> {
    _random_bits(n, 2.0 / 3.0, rng).into_iter()
        .map(|b| if b { C::ScalarField::one() } else { C::ScalarField::zero() })
        .collect()
}

pub(crate) fn random_pks<R: Rng, C: CurveGroup>(n: usize, rng: &mut R) -> Vec<C> {
    (0..n)
        .map(|_| C::rand(rng))
        .collect()
}

fn _test_prove_verify<IC, OC, S, D, ProofT, PI, P, V>(
    pcs_params: S::Params,
    prove: P,
    verify: V,
    keyset_size: usize,
    proof_size: usize
)
where
    IC: CurveGroup,
    OC: CurveGroup,
    OC::ScalarField: From<IC::BaseField> + FftField,
    S: PCS<OC::ScalarField>,
    D: crate::DomainFactory<OC::ScalarField>,
    S::C: CommitmentExt<OC::ScalarField, Affine = OC::Affine>,
    S::Params: Clone,
    ProofT: CanonicalSerialize + CanonicalDeserialize,
    PI: PublicInput<IC>,
    P: Fn(Prover<IC, OC, S, D>, Bitmask) -> (ProofT, PI),
    V: Fn(&Verifier<IC, OC, S, D>, &PI, &ProofT) -> bool,
{
    let rng = &mut test_rng();

    let keyset = Keyset::<IC, OC, D>::new(random_pks(keyset_size, rng));

    let pks_commitment_ = start_timer!(|| "signer set commitment");
    let pks_comm = keyset.commit::<S>(&pcs_params.ck());
    end_timer!(pks_commitment_);

    let t_prover_new = start_timer!(|| "prover precomputation");
    let prover = Prover::new(
        keyset,
        &pks_comm,
        pcs_params.clone(),
        Transcript::new(b"apk_proof")
    );
    end_timer!(t_prover_new);

    let verifier = Verifier::new(
        pcs_params.raw_vk(), 
        pks_comm, 
        Transcript::new(b"apk_proof")
    );

    let bits = (0..keyset_size).map(|_| rng.gen_bool(2.0 / 3.0)).collect::<Vec<_>>();
    let b = Bitmask::from_bits(&bits);

    let prove_ = start_timer!(|| "prove");
    let (proof, public_input) = prove(prover, b.clone());
    end_timer!(prove_);

    let mut serialized_proof = vec![0; proof.compressed_size()];
    proof.serialize_compressed(&mut serialized_proof[..]).unwrap();
    let deserialized_proof = ProofT::deserialize_compressed(&serialized_proof[..]).unwrap();

    assert_eq!(proof.compressed_size(), proof_size);

    let verify_ = start_timer!(|| "verify");
    let valid = verify(&verifier, &public_input, &deserialized_proof);
    end_timer!(verify_);

    assert!(valid);
}

pub fn test_simple_scheme(keyset_size: usize) {
    use ark_bls12_377::G1Projective as InnerCurve;
    use ark_bw6_761::{G1Projective as OuterCurve, Fr};
    use crate::AccountablePublicInput;

    type ProofType = SimpleProof<Fr, ark_bw6_761::G1Affine, w3f_pcs::pcs::kzg::commitment::KzgCommitment<ark_bw6_761::BW6_761>, ark_bw6_761::G1Affine>;

    _test_prove_verify::<InnerCurve, OuterCurve, Pcs, crate::Radix2Domain<Fr>, ProofType, AccountablePublicInput<InnerCurve>, _, _>(
        setup::generate_for_keyset::<_, Fr, Pcs, crate::Radix2Domain<Fr>>(keyset_size, &mut test_rng()),
        |prover, bitmask| prover.prove_simple(bitmask),
        |verifier, public_input, proof| verifier.verify_simple(public_input, proof),
        keyset_size,
        (5 * 2 + 6) * 48 // 5C + 6F
    );
}

pub fn test_packed_scheme(keyset_size: usize) {
    use ark_bls12_377::G1Projective as InnerCurve;
    use ark_bw6_761::{G1Projective as OuterCurve, Fr};
    use crate::AccountablePublicInput;

    type ProofType = PackedProof<Fr, ark_bw6_761::G1Affine, w3f_pcs::pcs::kzg::commitment::KzgCommitment<ark_bw6_761::BW6_761>, ark_bw6_761::G1Affine>;

    _test_prove_verify::<InnerCurve, OuterCurve, Pcs, crate::Radix2Domain<Fr>, ProofType, AccountablePublicInput<InnerCurve>, _, _>(
        setup::generate_for_keyset::<_, Fr, Pcs, crate::Radix2Domain<Fr>>(keyset_size, &mut test_rng()),
        |prover, bitmask| prover.prove_packed(bitmask),
        |verifier, public_input, proof| verifier.verify_packed(public_input, proof),
        keyset_size,
        (8 * 2 + 9) * 48 // 8C + 9F
    );
}

pub fn test_counting_scheme(keyset_size: usize) {
    use ark_bls12_377::G1Projective as InnerCurve;
    use ark_bw6_761::{G1Projective as OuterCurve, Fr};
    use crate::CountingPublicInput;

    type ProofType = CountingProof<Fr, ark_bw6_761::G1Affine, w3f_pcs::pcs::kzg::commitment::KzgCommitment<ark_bw6_761::BW6_761>, ark_bw6_761::G1Affine>;

    _test_prove_verify::<InnerCurve, OuterCurve, Pcs, crate::Radix2Domain<Fr>, ProofType, CountingPublicInput<InnerCurve>, _, _>(
        setup::generate_for_keyset::<_, Fr, Pcs, crate::Radix2Domain<Fr>>(keyset_size, &mut test_rng()),
        |prover, bitmask| prover.prove_counting(bitmask),
        |verifier, public_input, proof| verifier.verify_counting(public_input, proof),
        keyset_size,
        (7 * 2 + 8) * 48 // 7C + 8F
    );
}

// ---------------------------------------------------------------------------------------------
// APK-381: BLS12-381 / BW6-767
//
// The same protocol over a scalar field with two-adicity 1, so every domain is a divisor of
// 2 * 3^2 * 11 * 23 * 47 and none is a multiple of 4.
//
// Proofs are slightly LARGER than APK-377's, by one byte per group element. Field elements
// match at 48 bytes (BW6-767's scalar field is 381 bits, BW6-761's 377), but a compressed G1
// point takes 97 bytes here against 96 there: BW6-767's base field is 767 bits, which fills 96
// bytes to within one spare bit, leaving no room for the two flags arkworks needs for the
// infinity marker and the y-sign, so the encoding spills into a 97th byte. BW6-761's 761-bit
// base field leaves seven spare bits and stays at 96.
//
// `packed` is absent on purpose — it hardcodes 256-bit bitmask chunks and so needs 256 | n,
// which no BW6-767 domain satisfies.
// ---------------------------------------------------------------------------------------------

pub fn test_simple_scheme_381(keyset_size: usize) {
    use crate::instances::bls12_381_bw6_767::{
        kzg::Pcs as Pcs381, Domain767, InnerCurve, OuterCurve, OuterScalar,
    };
    use crate::AccountablePublicInput;

    type ProofType = SimpleProof<
        OuterScalar,
        ark_bw6_767::G1Affine,
        w3f_pcs::pcs::kzg::commitment::KzgCommitment<ark_bw6_767::BW6_767>,
        ark_bw6_767::G1Affine,
    >;

    _test_prove_verify::<
        InnerCurve,
        OuterCurve,
        Pcs381,
        Domain767,
        ProofType,
        AccountablePublicInput<InnerCurve>,
        _,
        _,
    >(
        crate::instances::bls12_381_bw6_767::kzg::generate_urs(
            3 * Domain767::create_domain(keyset_size + 1).size() - 3,
            &mut test_rng(),
        ),
        |prover, bitmask| prover.prove_simple(bitmask),
        |verifier, public_input, proof| verifier.verify_simple(public_input, proof),
        keyset_size,
        5 * 97 + 6 * 48, // 5C + 6F
    );
}

pub fn test_counting_scheme_381(keyset_size: usize) {
    use crate::instances::bls12_381_bw6_767::{
        kzg::Pcs as Pcs381, Domain767, InnerCurve, OuterCurve, OuterScalar,
    };
    use crate::CountingPublicInput;

    type ProofType = CountingProof<
        OuterScalar,
        ark_bw6_767::G1Affine,
        w3f_pcs::pcs::kzg::commitment::KzgCommitment<ark_bw6_767::BW6_767>,
        ark_bw6_767::G1Affine,
    >;

    _test_prove_verify::<
        InnerCurve,
        OuterCurve,
        Pcs381,
        Domain767,
        ProofType,
        CountingPublicInput<InnerCurve>,
        _,
        _,
    >(
        crate::instances::bls12_381_bw6_767::kzg::generate_urs(
            3 * Domain767::create_domain(keyset_size + 1).size() - 3,
            &mut test_rng(),
        ),
        |prover, bitmask| prover.prove_counting(bitmask),
        |verifier, public_input, proof| verifier.verify_counting(public_input, proof),
        keyset_size,
        7 * 97 + 8 * 48, // 7C + 8F
    );
}
/// `prove_packed` must not exist on APK-381. This function is never called; it is here so the
/// gate is visible, and so that deleting `SupportsPackedScheme` would be caught by the doc test
/// below rather than silently re-enabling a scheme that cannot work.
///
/// ```compile_fail
/// use apk_proofs::instances::bls12_381_bw6_767::kzg::Prover381;
/// fn f(p: &Prover381, b: apk_proofs::Bitmask) {
///     let _ = p.prove_packed(b);
/// }
/// ```
///
/// The same call compiles for APK-377:
/// ```
/// use apk_proofs::instances::bls12_377_bw6_761::kzg::ProverBls12_377Bw6_761Kzg as P377;
/// fn f(p: &P377, b: apk_proofs::Bitmask) {
///     let _ = p.prove_packed(b);
/// }
/// ```
pub fn _packed_scheme_is_gated_to_apk_377() {}

// ---------------------------------------------------------------------------------------------
// Negative tests
//
// Everything above checks that an honest proof verifies. These check that dishonest ones do not,
// which is the property that actually matters and the one a refactor is most likely to break
// silently: a verifier that ignores part of its input still passes every positive test.
// ---------------------------------------------------------------------------------------------

/// Builds an honest prover/verifier pair, then asserts that verification fails once the claim
/// no longer matches the proof.
fn _test_rejects_tampering<IC, OC, S, D>(
    pcs_params: S::Params,
    keyset_size: usize,
) where
    IC: CurveGroup,
    OC: CurveGroup,
    OC::ScalarField: From<IC::BaseField> + FftField,
    S: PCS<OC::ScalarField>,
    D: crate::DomainFactory<OC::ScalarField>,
    S::C: CommitmentExt<OC::ScalarField, Affine = OC::Affine> + Clone,
    S::Params: Clone,
{
    let rng = &mut test_rng();

    let keyset = Keyset::<IC, OC, D>::new(random_pks(keyset_size, rng));
    let pks_comm = keyset.commit::<S>(&pcs_params.ck());
    let prover = Prover::<IC, OC, S, D>::new(
        keyset,
        &pks_comm,
        pcs_params.clone(),
        Transcript::new(b"apk_proof"),
    );
    let verifier = Verifier::<IC, OC, S, D>::new(
        pcs_params.raw_vk(),
        pks_comm.clone(),
        Transcript::new(b"apk_proof"),
    );

    let bits: Vec<bool> = (0..keyset_size).map(|_| rng.gen_bool(2.0 / 3.0)).collect();
    let (proof, public_input) = prover.prove_simple(Bitmask::from_bits(&bits));

    // Sanity: the honest claim verifies, so any failure below is caused by the tampering.
    assert!(
        verifier.verify_simple(&public_input, &proof),
        "the honest proof must verify"
    );

    // Flipping a bit changes the claimed signer set. The bitmask feeds the transcript, so this
    // moves every challenge, and it also breaks the aggregate-key relation.
    let mut flipped = bits.clone();
    flipped[0] = !flipped[0];
    let tampered = crate::AccountablePublicInput::<IC>::new(&public_input.apk, &Bitmask::from_bits(&flipped));
    assert!(
        !verifier.verify_simple(&tampered, &proof),
        "a proof must not verify against a different bitmask"
    );

    // Claiming a different aggregate key for the same bitmask.
    let wrong_apk = crate::AccountablePublicInput::<IC>::new(
        &(public_input.apk.into_group() + IC::generator()).into_affine(),
        &Bitmask::from_bits(&bits),
    );
    assert!(
        !verifier.verify_simple(&wrong_apk, &proof),
        "a proof must not verify against a different aggregate key"
    );

    // A verifier that disagrees with the prover about the domain must reject. This is what the
    // domain size and generator in the transcript are for: without them the two sides could
    // silently be working over different domains.
    let mut wrong_domain_comm = pks_comm;
    wrong_domain_comm.domain_size *= 2;
    let wrong_domain_verifier = Verifier::<IC, OC, S, D>::new(
        pcs_params.raw_vk(),
        wrong_domain_comm,
        Transcript::new(b"apk_proof"),
    );
    assert!(
        !wrong_domain_verifier.verify_simple(&public_input, &proof),
        "a proof must not verify against a verifier using a different domain"
    );
}

/// A keyset commitment arrives from the chain, so its domain size is untrusted. Neither a size
/// the field cannot realise exactly, nor one no field could realise, may panic the verifier.
fn _test_rejects_bad_domain_size<IC, OC, S, D>(pcs_params: S::Params, keyset_size: usize, unrealisable: u64)
where
    IC: CurveGroup,
    OC: CurveGroup,
    OC::ScalarField: From<IC::BaseField> + FftField,
    S: PCS<OC::ScalarField>,
    D: crate::DomainFactory<OC::ScalarField>,
    S::C: CommitmentExt<OC::ScalarField, Affine = OC::Affine> + Clone,
    S::Params: Clone,
{
    let rng = &mut test_rng();
    let keyset = Keyset::<IC, OC, D>::new(random_pks(keyset_size, rng));
    let pks_comm = keyset.commit::<S>(&pcs_params.ck());

    let mut not_exact = pks_comm.clone();
    not_exact.domain_size = unrealisable;
    assert!(
        matches!(
            Verifier::<IC, OC, S, D>::try_new(pcs_params.raw_vk(), not_exact, Transcript::new(b"apk_proof")),
            Err(crate::DomainError::NotExact { .. })
        ),
        "a domain size the field cannot realise exactly must be rejected"
    );

    let mut too_large = pks_comm;
    too_large.domain_size = u64::MAX;
    assert!(
        matches!(
            Verifier::<IC, OC, S, D>::try_new(pcs_params.raw_vk(), too_large, Transcript::new(b"apk_proof")),
            Err(crate::DomainError::TooLarge { .. })
        ),
        "an unrealisable domain size must be rejected"
    );
}

pub fn test_rejects_bad_domain_size_377(keyset_size: usize) {
    use ark_bls12_377::G1Projective as InnerCurve;
    use ark_bw6_761::{Fr, G1Projective as OuterCurve};

    // 255 is not a power of two.
    _test_rejects_bad_domain_size::<InnerCurve, OuterCurve, Pcs, crate::Radix2Domain<Fr>>(
        setup::generate_for_keyset::<_, Fr, Pcs, crate::Radix2Domain<Fr>>(keyset_size, &mut test_rng()),
        keyset_size,
        255,
    );
}

pub fn test_rejects_bad_domain_size_381(keyset_size: usize) {
    use crate::instances::bls12_381_bw6_767::{kzg::Pcs as Pcs381, Domain767, InnerCurve, OuterCurve};

    // 254 = 2 * 127 does not divide q - 1.
    _test_rejects_bad_domain_size::<InnerCurve, OuterCurve, Pcs381, Domain767>(
        crate::instances::bls12_381_bw6_767::kzg::generate_urs(
            3 * Domain767::create_domain(keyset_size + 1).size() - 3,
            &mut test_rng(),
        ),
        keyset_size,
        254,
    );
}

pub fn test_rejects_tampering_377(keyset_size: usize) {
    use ark_bls12_377::G1Projective as InnerCurve;
    use ark_bw6_761::{Fr, G1Projective as OuterCurve};

    _test_rejects_tampering::<InnerCurve, OuterCurve, Pcs, crate::Radix2Domain<Fr>>(
        setup::generate_for_keyset::<_, Fr, Pcs, crate::Radix2Domain<Fr>>(
            keyset_size,
            &mut test_rng(),
        ),
        keyset_size,
    );
}

pub fn test_rejects_tampering_381(keyset_size: usize) {
    use crate::instances::bls12_381_bw6_767::{kzg::Pcs as Pcs381, Domain767, InnerCurve, OuterCurve};

    _test_rejects_tampering::<InnerCurve, OuterCurve, Pcs381, Domain767>(
        crate::instances::bls12_381_bw6_767::kzg::generate_urs(
            3 * Domain767::create_domain(keyset_size + 1).size() - 3,
            &mut test_rng(),
        ),
        keyset_size,
    );
}

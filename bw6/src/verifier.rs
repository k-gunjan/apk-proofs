use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_std::{end_timer, start_timer};
use merlin::{Transcript as MerlinTranscript, TranscriptRng};
use w3f_pcs::aggregation::single::aggregate_claims_multiexp;
use w3f_pcs::pcs::{PcsParams, RawVerifierKey, PCS};

use crate::domain::{DomainSet, FftDomain};
use crate::fsrng::fiat_shamir_rng;
use crate::piop::affine_addition::AffineAdditionEvaluations;
use crate::piop::bitmask_packing::SuccinctAccountableRegisterEvaluations;
use crate::piop::counting::CountingEvaluations;
use crate::piop::{RegisterCommitments, RegisterEvaluations, VerifierProtocol};
use crate::transcript::ApkTranscript;
use crate::utils::LagrangeEvaluations;
use crate::{
    utils, AccountablePublicInput, AccumulatorSeed, ApkError, CommitmentExt, CountingProof,
    CountingPublicInput, KeysetCommitment, PackedProof, Proof, PublicInput, SimpleProof,
};

type Transcript = MerlinTranscript;

pub struct Challenges<F: FftField> {
    pub r: F,
    pub phi: F,
    pub zeta: F,
    pub nus: Vec<F>,
}

pub struct Verifier<IC, OC, S, D>
where
    IC: AccumulatorSeed,
    OC: CurveGroup,
    OC::ScalarField: From<IC::BaseField> + FftField,
    S: PCS<OC::ScalarField>,
    D: DomainSet<OC::ScalarField>,
{
    domain: D::Domain,
    verifier_key: <S::Params as PcsParams>::RVK,
    pks_comm: KeysetCommitment<OC::ScalarField, S::C>,
    preprocessed_transcript: Transcript,
    _marker: std::marker::PhantomData<(IC, S)>,
}

impl<IC, OC, S, D> Verifier<IC, OC, S, D>
where
    IC: AccumulatorSeed,
    OC: CurveGroup,
    OC::ScalarField: From<IC::BaseField> + FftField,
    S: PCS<OC::ScalarField>,
    S::C: CommitmentExt<OC::ScalarField, Affine = OC::Affine> + Clone,
    D: DomainSet<OC::ScalarField>,
{
    /// The sizes come out of the keyset commitment, which for a bridge arrives from the chain.
    /// The commitment is signed by the validators, so the sizes are trusted to be what they
    /// signed — but not to be usable: the domain size may name one this field cannot realise,
    /// or the key count may not fit it. Both are rejected rather than panicking.
    ///
    /// Everything checked here is checked once per keyset rather than once per proof.
    pub fn try_new(
        verifier_key: <S::Params as PcsParams>::RVK,
        pks_comm: KeysetCommitment<OC::ScalarField, S::C>,
        mut empty_transcript: Transcript,
    ) -> Result<Self, ApkError> {
        // At least one key, and every key on a row below the last, which is reserved. The
        // cheap check goes first: building the domain is not free.
        if pks_comm.keyset_size == 0 || pks_comm.keyset_size >= pks_comm.domain_size {
            return Err(ApkError::InvalidKeysetCommitment {
                keyset_size: pks_comm.keyset_size,
                domain_size: pks_comm.domain_size,
            });
        }
        let domain_size = pks_comm.domain_size as usize;
        let domain = D::base_for_exact_size(domain_size)?;

        <Transcript as ApkTranscript<OC::ScalarField>>::set_protocol_params(
            &mut empty_transcript,
            &domain,
            &verifier_key,
        );
        <Transcript as ApkTranscript<OC::ScalarField>>::set_keyset_commitment(
            &mut empty_transcript,
            &pks_comm,
        );

        Ok(Self {
            domain,
            verifier_key,
            pks_comm,
            preprocessed_transcript: empty_transcript,
            _marker: std::marker::PhantomData,
        })
    }

    /// `Ok(false)` for a proof that does not verify; `Err` for a public input that is malformed
    /// before any proof is looked at.
    pub fn verify_simple(
        &self,
        public_input: &AccountablePublicInput<IC>,
        proof: &SimpleProof<OC::ScalarField, OC::Affine, S::C, S::Proof>,
    ) -> Result<bool, ApkError> {
        self.check_bitmask_length(&public_input.bitmask)?;
        let (challenges, mut fsrng) = self.restore_challenges(
            public_input,
            proof,
            <AffineAdditionEvaluations<OC::ScalarField> as VerifierProtocol<IC, OC, S>>::POLYS_OPENED_AT_ZETA
        );
        let evals_at_zeta = utils::lagrange_evaluations(challenges.zeta, &self.domain);

        let t_linear_accountability = start_timer!(|| "linear accountability check");
        let b_at_zeta =
            utils::barycentric_eval_binary_at(challenges.zeta, &public_input.bitmask, &self.domain);
        end_timer!(t_linear_accountability);

        let evaluations_with_bitmask = AffineAdditionEvaluations {
            keyset: proof.register_evaluations.keyset,
            bitmask: b_at_zeta,
            partial_sums: proof.register_evaluations.partial_sums,
        };

        let openings_valid = self.validate_evaluations(
            proof,
            &evaluations_with_bitmask,
            &challenges,
            &mut fsrng,
            &evals_at_zeta,
        );

        let apk = public_input.apk;
        let constraint_polynomial_evals = evaluations_with_bitmask
            .evaluate_constraint_polynomials::<IC, OC>(&apk, &evals_at_zeta)?;
        let w = utils::horner_field(&constraint_polynomial_evals, challenges.phi);
        Ok(openings_valid
            && (proof.r_zeta_omega + w == proof.q_zeta * evals_at_zeta.vanishing_polynomial))
    }

    /// See [`Self::verify_simple`].
    pub fn verify_packed(
        &self,
        public_input: &AccountablePublicInput<IC>,
        proof: &PackedProof<OC::ScalarField, OC::Affine, S::C, S::Proof>,
    ) -> Result<bool, ApkError> {
        self.check_bitmask_length(&public_input.bitmask)?;
        let (challenges, mut fsrng) = self.restore_challenges(
            public_input,
            proof,
            <SuccinctAccountableRegisterEvaluations<OC::ScalarField> as VerifierProtocol<
                IC,
                OC,
                S,
            >>::POLYS_OPENED_AT_ZETA,
        );
        let evals_at_zeta = utils::lagrange_evaluations(challenges.zeta, &self.domain);

        let openings_valid = self.validate_evaluations(
            proof,
            &proof.register_evaluations,
            &challenges,
            &mut fsrng,
            &evals_at_zeta,
        );

        let apk = public_input.apk;
        let constraint_polynomial_evals = proof
            .register_evaluations
            .evaluate_constraint_polynomials::<IC, OC>(
                &apk,
                &evals_at_zeta,
                challenges.r,
                &public_input.bitmask,
                self.domain.size() as u64,
            )?;
        let w = utils::horner_field(&constraint_polynomial_evals, challenges.phi);
        Ok(openings_valid
            && (proof.r_zeta_omega + w == proof.q_zeta * evals_at_zeta.vanishing_polynomial))
    }

    /// See [`Self::verify_simple`].
    pub fn verify_counting(
        &self,
        public_input: &CountingPublicInput<IC>,
        proof: &CountingProof<OC::ScalarField, OC::Affine, S::C, S::Proof>,
    ) -> Result<bool, ApkError> {
        let keyset_size = self.keyset_size();
        if public_input.count == 0 || public_input.count > keyset_size {
            return Err(ApkError::CountOutOfRange {
                count: public_input.count,
                keyset_size,
            });
        }
        let (challenges, mut fsrng) = self.restore_challenges(
            public_input,
            proof,
            <CountingEvaluations<OC::ScalarField> as VerifierProtocol<IC, OC, S>>::POLYS_OPENED_AT_ZETA
        );
        let evals_at_zeta = utils::lagrange_evaluations(challenges.zeta, &self.domain);
        let count = OC::ScalarField::from(public_input.count as u32);

        let openings_valid = self.validate_evaluations(
            proof,
            &proof.register_evaluations,
            &challenges,
            &mut fsrng,
            &evals_at_zeta,
        );

        let apk = public_input.apk;
        let constraint_polynomial_evals = proof
            .register_evaluations
            .evaluate_constraint_polynomials::<IC, OC>(apk, count, &evals_at_zeta)?;
        let w = utils::horner_field(&constraint_polynomial_evals, challenges.phi);
        Ok(openings_valid
            && (proof.r_zeta_omega + w == proof.q_zeta * evals_at_zeta.vanishing_polynomial))
    }

    fn keyset_size(&self) -> usize {
        self.pks_comm.keyset_size as usize
    }

    /// One bit per key, exactly. The verifier folds the bitmask into a polynomial over the
    /// domain, so extra bits would not be ignored: they would land on padding rows, or wrap
    /// around onto real keys and report signers under the wrong index.
    fn check_bitmask_length(&self, bitmask: &crate::Bitmask) -> Result<(), ApkError> {
        if bitmask.size() != self.keyset_size() {
            return Err(ApkError::BitmaskLengthMismatch {
                bitmask: bitmask.size(),
                keyset: self.keyset_size(),
            });
        }
        Ok(())
    }

    fn validate_evaluations<E, C, AC, P>(
        &self,
        proof: &Proof<OC::ScalarField, E, C, AC, S::C, S::Proof>,
        protocol: &P,
        challenges: &Challenges<OC::ScalarField>,
        fsrng: &mut TranscriptRng,
        evals_at_zeta: &LagrangeEvaluations<OC::ScalarField>,
    ) -> bool
    where
        E: RegisterEvaluations<OC::ScalarField>,
        C: RegisterCommitments<OC::Affine>,
        AC: RegisterCommitments<OC::Affine>,
        P: VerifierProtocol<IC, OC, S, C1 = C, C2 = AC>,
    {
        let t_pcs = start_timer!(|| "PCS verification");

        // Reconstruct the commitment to the linearization polynomial
        let t_r_comm = start_timer!(|| "linearization polynomial commitment");
        let r_comm = protocol
            .restore_commitment_to_linearization_polynomial(
                challenges.phi,
                evals_at_zeta.zeta_minus_omega_inv,
                &proof.register_commitments,
                &proof.additional_commitments,
            )
            .into_affine();
        end_timer!(t_r_comm);

        // Aggregate the commitments to be opened at ζ
        let t_aggregate_claims = start_timer!(|| "aggregate evaluation claims at zeta");
        let mut commitment_points = vec![
            self.pks_comm.pks_comm.0.to_affine(),
            self.pks_comm.pks_comm.1.to_affine(),
        ];
        commitment_points.extend(proof.register_commitments.as_vec());
        commitment_points.extend(proof.additional_commitments.as_vec());
        commitment_points.push(proof.q_comm.to_affine());

        let mut register_evals = proof.register_evaluations.as_vec();
        register_evals.push(proof.q_zeta);

        // Both lengths are fixed by the proof type, and `nus` was drawn for exactly that many.
        debug_assert_eq!(commitment_points.len(), challenges.nus.len());
        debug_assert_eq!(register_evals.len(), challenges.nus.len());

        let (w_comm_affine, w_at_zeta) =
            aggregate_claims_multiexp(commitment_points, register_evals, &challenges.nus);
        end_timer!(t_aggregate_claims);

        // Batch verify the two opening proofs
        let t_batch_opening = start_timer!(|| "batched PCS opening verification");

        // Convert affine points back to commitments
        let w_comm = S::C::from_affine(w_comm_affine);
        let r_comm_wrapped = S::C::from_affine(r_comm);

        // Prepare vectors for batch verification
        let commitments = vec![w_comm, r_comm_wrapped];
        let points = vec![challenges.zeta, evals_at_zeta.zeta_omega];
        let values = vec![w_at_zeta, proof.r_zeta_omega];
        let proofs = vec![
            proof.w_at_zeta_proof.clone(),
            proof.r_at_zeta_omega_proof.clone(),
        ];

        let verified = S::batch_verify(
            &self.verifier_key.prepare(),
            commitments,
            points,
            values,
            proofs,
            fsrng, // Use the transcript RNG for randomness
        )
        .is_ok();

        end_timer!(t_batch_opening);
        end_timer!(t_pcs);
        // Returned rather than asserted: proofs come from untrusted sources, so a failed
        // opening check is an invalid proof to reject, not a reason to abort the process.
        verified
    }

    fn restore_challenges<E, C, AC>(
        &self,
        public_input: &impl PublicInput<IC>,
        proof: &Proof<OC::ScalarField, E, C, AC, S::C, S::Proof>,
        batch_size: usize,
    ) -> (Challenges<OC::ScalarField>, TranscriptRng)
    where
        E: RegisterEvaluations<OC::ScalarField>,
        C: RegisterCommitments<OC::Affine>,
        AC: RegisterCommitments<OC::Affine>,
    {
        let mut transcript = self.preprocessed_transcript.clone();

        <Transcript as ApkTranscript<OC::ScalarField>>::append_public_input(
            &mut transcript,
            public_input,
        );
        <Transcript as ApkTranscript<OC::ScalarField>>::append_register_commitments(
            &mut transcript,
            &proof.register_commitments,
        );
        let r = <Transcript as ApkTranscript<OC::ScalarField>>::get_bitmask_aggregation_challenge(
            &mut transcript,
        );
        <Transcript as ApkTranscript<OC::ScalarField>>::append_2nd_round_register_commitments(
            &mut transcript,
            &proof.additional_commitments,
        );
        let phi =
            <Transcript as ApkTranscript<OC::ScalarField>>::get_constraints_aggregation_challenge(
                &mut transcript,
            );
        <Transcript as ApkTranscript<OC::ScalarField>>::append_quotient_commitment(
            &mut transcript,
            &proof.q_comm,
        );
        let zeta =
            <Transcript as ApkTranscript<OC::ScalarField>>::get_evaluation_point(&mut transcript);
        <Transcript as ApkTranscript<OC::ScalarField>>::append_evaluations(
            &mut transcript,
            &proof.register_evaluations,
            &proof.q_zeta,
            &proof.r_zeta_omega,
        );
        let nus =
            <Transcript as ApkTranscript<OC::ScalarField>>::get_opening_aggregation_challenges(
                &mut transcript,
                batch_size,
            );

        (
            Challenges { r, phi, zeta, nus },
            fiat_shamir_rng(&mut transcript),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::setup::InsecureSetup;
    use crate::test_helpers::random_pks;
    use crate::{
        AccountablePublicInputOf, AccumulatorSeed, Apk, ApkConfig, ApkError, Bitmask,
        Bls12_377Config, Bls12_381Config, CommitmentExt, CountingPublicInputOf, PcsParamsOf,
        ScalarOf, VerifierOf,
    };
    use ark_ec::CurveGroup;
    use ark_std::test_rng;
    use w3f_pcs::pcs::{PcsParams, PCS};

    fn check_rejects_malformed_inputs<C>()
    where
        C: ApkConfig,
        ScalarOf<C>: From<<C::InnerCurve as CurveGroup>::BaseField> + ark_ff::FftField,
        <C::Pcs as PCS<ScalarOf<C>>>::C:
            CommitmentExt<ScalarOf<C>, Affine = <C::OuterCurve as CurveGroup>::Affine> + Clone,
        PcsParamsOf<C>: Clone,
        InsecureSetup: crate::setup::PcsSetup<ScalarOf<C>, C::Pcs>,
    {
        let rng = &mut test_rng();
        let n = 10;
        let params = Apk::<C>::setup(&mut InsecureSetup::new(rng), n).unwrap();
        let (keyset, commitment) = Apk::<C>::commit_keyset(&params, random_pks(n, rng)).unwrap();
        let domain_size = commitment.domain_size as usize;
        assert_eq!(commitment.keyset_size, n as u64);

        // The commitment: at least one key, and fewer keys than the domain has rows.
        for bad in [0, commitment.domain_size, commitment.domain_size + 1] {
            let mut comm = commitment.clone();
            comm.keyset_size = bad;
            assert!(matches!(
                VerifierOf::<C>::try_new(params.raw_vk(), comm, C::transcript()),
                Err(ApkError::InvalidKeysetCommitment { .. })
            ));
        }

        let mut bits = vec![false; n];
        bits[2] = true;
        let (proof, public_input) = Apk::<C>::prove(
            &params,
            keyset.clone(),
            &commitment,
            Bitmask::from_bits(&bits),
        )
        .unwrap();
        assert_eq!(
            Apk::<C>::verify(&params, commitment.clone(), &public_input, &proof),
            Ok(true)
        );

        // Bit `domain_size + 2` evaluates at the same point as bit 2, so without the length
        // check this bitmask would name a signer who does not exist.
        let mut aliased = vec![false; 2 * domain_size];
        aliased[domain_size + 2] = true;
        for bits in [aliased, vec![true; n - 1], vec![true; n + 1]] {
            let forged = AccountablePublicInputOf::<C> {
                apk: public_input.apk,
                bitmask: Bitmask::from_bits(&bits),
            };
            assert_eq!(
                Apk::<C>::verify(&params, commitment.clone(), &forged, &proof),
                Err(ApkError::BitmaskLengthMismatch {
                    bitmask: bits.len(),
                    keyset: n
                })
            );
        }

        // An apk with h + apk = 0 has no affine form to evaluate the constraints at.
        let forged = AccountablePublicInputOf::<C> {
            apk: (-C::InnerCurve::accumulator_seed().into()).into_affine(),
            bitmask: Bitmask::from_bits(&bits),
        };
        assert_eq!(
            Apk::<C>::verify(&params, commitment.clone(), &forged, &proof),
            Err(ApkError::InvalidPublicInput(
                "apk is the negated accumulator seed"
            ))
        );

        // Counting: between 1 and the keyset size.
        let (proof, public_input) =
            Apk::<C>::prove_counting(&params, keyset, &commitment, Bitmask::from_bits(&bits))
                .unwrap();
        for count in [0, n + 1] {
            let forged = CountingPublicInputOf::<C> {
                apk: public_input.apk,
                count,
            };
            assert_eq!(
                Apk::<C>::verify_counting(&params, commitment.clone(), &forged, &proof),
                Err(ApkError::CountOutOfRange {
                    count,
                    keyset_size: n
                })
            );
        }
        assert_eq!(
            Apk::<C>::verify_counting(&params, commitment, &public_input, &proof),
            Ok(true)
        );
    }

    #[test]
    fn rejects_malformed_inputs() {
        check_rejects_malformed_inputs::<Bls12_377Config>();
        check_rejects_malformed_inputs::<Bls12_381Config>();
    }
}

use ark_ec::CurveGroup;
use ark_poly::univariate::DensePolynomial;
use ark_poly::Polynomial;
use merlin::Transcript;
use w3f_pcs::pcs::{CommitterKey, PcsParams, PCS};

use crate::domain::{DomainSet, FftDomain};
use crate::domains::Domains;
use crate::piop::basic::BasicRegisterBuilder;
use crate::piop::counting::CountingScheme;
use crate::piop::packed::PackedRegisterBuilder;
use crate::piop::ProverProtocol;
use crate::piop::RegisterPolynomials;
use crate::transcript::ApkTranscript;
use crate::{
    AccountablePublicInput, AccumulatorSeed, ApkError, Bitmask, CommitmentExt, CountingProof,
    CountingPublicInput, Keyset, KeysetCommitment, PackedProof, Proof, PublicInput, SimpleProof,
};

pub struct Prover<IC, OC, S, D>
where
    IC: AccumulatorSeed,
    OC: CurveGroup,
    OC::ScalarField: From<IC::BaseField>,
    S: PCS<OC::ScalarField>,
    D: DomainSet<OC::ScalarField>,
{
    domains: Domains<OC::ScalarField, D>,
    keyset: Keyset<IC, OC, D>,
    committer_key: S::CK,
    preprocessed_transcript: Transcript,
}

impl<IC, OC, S, D> Prover<IC, OC, S, D>
where
    IC: AccumulatorSeed,
    OC: CurveGroup,
    OC::ScalarField: From<IC::BaseField>,
    S: PCS<OC::ScalarField>,
    S::C: CommitmentExt<OC::ScalarField, Affine = OC::Affine>,
    D: DomainSet<OC::ScalarField>,
{
    pub fn new(
        mut keyset: Keyset<IC, OC, D>,
        keyset_comm: &KeysetCommitment<OC::ScalarField, S::C>,
        // prover needs both the committer and the verifier key, as it commits to the latter
        // to bind the srs
        pcs_params: S::Params,
        mut empty_transcript: Transcript,
    ) -> Result<Self, ApkError> {
        let domains = Domains::from_set(keyset.domains.clone());
        let committer_key = pcs_params.ck();

        // The SRS has to cover the quotient, which is the highest-degree thing the prover
        // commits to — `3n - 3`, not `n`. Checked here rather than left to the commitment that
        // needs it: `Keyset::commit` only needs degree `n - 1` and so happily succeeds against
        // parameters this prover will later fail on, and that failure lands inside a commit
        // closure as an opaque `Err(())`.
        //
        // Reachable whenever the SRS was generated for fewer keys than the keyset holds, since
        // nothing ties `Apk::setup`'s argument to the length of the vector passed to
        // `commit_keyset`.
        let required = crate::setup::highest_degree_to_commit(keyset.domain().size());
        if required > committer_key.max_degree() {
            return Err(ApkError::SrsTooSmall {
                domain_size: keyset.domain().size(),
                required_degree: required,
                available_degree: committer_key.max_degree(),
            });
        }

        <Transcript as ApkTranscript<OC::ScalarField>>::set_protocol_params(
            &mut empty_transcript,
            keyset.domain(),
            &pcs_params.raw_vk(),
        );
        <Transcript as ApkTranscript<OC::ScalarField>>::set_keyset_commitment(
            &mut empty_transcript,
            keyset_comm,
        );

        keyset.amplify();

        Ok(Self {
            domains,
            keyset,
            committer_key,
            preprocessed_transcript: empty_transcript,
        })
    }

    pub fn prove_simple(
        &self,
        bitmask: Bitmask,
    ) -> Result<
        (
            SimpleProof<OC::ScalarField, OC::Affine, S::C, S::Proof>,
            AccountablePublicInput<IC>,
        ),
        ApkError,
    > {
        self.prove::<BasicRegisterBuilder<OC::ScalarField, D>>(bitmask)
    }

    pub fn prove_counting(
        &self,
        bitmask: Bitmask,
    ) -> Result<
        (
            CountingProof<OC::ScalarField, OC::Affine, S::C, S::Proof>,
            CountingPublicInput<IC>,
        ),
        ApkError,
    > {
        self.prove::<CountingScheme<OC::ScalarField, D>>(bitmask)
    }

    fn prove<P>(
        &self,
        bitmask: Bitmask,
    ) -> Result<
        (
            Proof<
                OC::ScalarField,
                P::E,
                <P::P1 as RegisterPolynomials<OC::Affine>>::C,
                <P::P2 as RegisterPolynomials<OC::Affine>>::C,
                S::C,
                S::Proof,
            >,
            P::PI,
        ),
        ApkError,
    >
    where
        P: ProverProtocol<IC, OC, S, D>,
    {
        if bitmask.size() != self.keyset.size() {
            return Err(ApkError::BitmaskLengthMismatch {
                bitmask: bitmask.size(),
                keyset: self.keyset.size(),
            });
        }
        let bits = bitmask.to_bits();
        // Checked on the bits themselves rather than `count_ones`, which also counts padding
        // bits, and a deserialized bitmask may have those set.
        // The EC identity doesn't have an affine representation.
        if !bits.iter().any(|b| *b) {
            return Err(ApkError::NoSigners);
        }

        let apk = self.keyset.aggregate(&bits)?.into_affine();

        let mut transcript = self.preprocessed_transcript.clone();
        let public_input = P::PI::new(&apk, &bitmask);
        <Transcript as ApkTranscript<OC::ScalarField>>::append_public_input(
            &mut transcript,
            &public_input,
        );

        // 1. Compute and commit to the basic registers.
        let mut protocol = P::init(self.domains.clone(), bitmask, self.keyset.clone());
        let partial_sums_polynomials = protocol.get_register_polynomials_to_commit1();
        let partial_sums_commitments =
            partial_sums_polynomials.commit(|p| self.commit(p, "commit to 1st round registers"))?;

        <Transcript as ApkTranscript<OC::ScalarField>>::append_register_commitments(
            &mut transcript,
            &partial_sums_commitments,
        );

        // 2. Receive bitmask aggregation challenge,
        // compute and commit to succinct accountability registers.
        let r = <Transcript as ApkTranscript<OC::ScalarField>>::get_bitmask_aggregation_challenge(
            &mut transcript,
        );
        // let acc_registers = D::wrap(registers, b, r);
        let acc_register_polynomials = protocol.get_register_polynomials_to_commit2(r);
        let acc_register_commitments =
            acc_register_polynomials.commit(|p| self.commit(p, "commit to 2nd round registers"))?;
        <Transcript as ApkTranscript<OC::ScalarField>>::append_2nd_round_register_commitments(
            &mut transcript,
            &acc_register_commitments,
        );

        // 3. Receive constraint aggregation challenge,
        // compute and commit to the quotient polynomial.
        let phi =
            <Transcript as ApkTranscript<OC::ScalarField>>::get_constraints_aggregation_challenge(
                &mut transcript,
            );
        let q_poly = protocol.compute_quotient_polynomial(phi, self.keyset.domain())?;
        let q_comm = S::commit(&self.committer_key, &q_poly)
            .map_err(|_| ApkError::Pcs("commit to quotient"))?;
        <Transcript as ApkTranscript<OC::ScalarField>>::append_quotient_commitment(
            &mut transcript,
            &q_comm,
        );

        // 4. Receive the evaluation point,
        // evaluate register polynomials and the quotient polynomial,
        // compute the linearization polynomial and evaluate it at the shifted evaluation point,
        // commit to all the evaluations.
        let zeta =
            <Transcript as ApkTranscript<OC::ScalarField>>::get_evaluation_point(&mut transcript);
        let register_evaluations = protocol.evaluate_register_polynomials(zeta);
        let q_zeta = q_poly.evaluate(&zeta);
        let zeta_omega = zeta * self.keyset.domain().generator();
        let r_poly = protocol.compute_linearization_polynomial(phi, zeta);
        let r_zeta_omega = r_poly.evaluate(&zeta_omega);
        <Transcript as ApkTranscript<OC::ScalarField>>::append_evaluations(
            &mut transcript,
            &register_evaluations,
            &q_zeta,
            &r_zeta_omega,
        );

        // 5. Receive the polynomials aggregation challenge,
        // open the aggregated polynomial at the evaluation point,
        // and the linearization polynomial at the shifted evaluation point,
        // and commit to the opening proofs.
        let mut register_polynomials = protocol.get_register_polynomials_to_open();
        register_polynomials.push(q_poly);
        let nus =
            <Transcript as ApkTranscript<OC::ScalarField>>::get_opening_aggregation_challenges(
                &mut transcript,
                register_polynomials.len(),
            );
        let w_poly = w3f_pcs::aggregation::single::aggregate_polys(&register_polynomials, &nus);
        let w_at_zeta_proof = S::open(&self.committer_key, &w_poly, zeta)
            .map_err(|_| ApkError::Pcs("open at zeta"))?;
        let r_at_zeta_omega_proof = S::open(&self.committer_key, &r_poly, zeta_omega)
            .map_err(|_| ApkError::Pcs("open at zeta * omega"))?;

        // Finally, compose the proof.
        let proof = Proof {
            register_commitments: partial_sums_commitments,
            additional_commitments: acc_register_commitments,
            // phi <-
            q_comm,
            // zeta <-
            register_evaluations,
            q_zeta,
            r_zeta_omega,
            // <- nu
            w_at_zeta_proof,
            r_at_zeta_omega_proof,
        };

        Ok((proof, public_input))
    }

    fn commit(
        &self,
        poly: &DensePolynomial<OC::ScalarField>,
        step: &'static str,
    ) -> Result<OC::Affine, ApkError> {
        S::commit(&self.committer_key, poly)
            .map(|c| c.to_affine())
            .map_err(|_| ApkError::Pcs(step))
    }
}

/// The packed scheme is only available where the domain can supply sizes divisible by 256.
/// See [`SupportsPackedScheme`](crate::SupportsPackedScheme).
impl<IC, OC, S, D> Prover<IC, OC, S, D>
where
    IC: AccumulatorSeed,
    OC: CurveGroup,
    OC::ScalarField: From<IC::BaseField>,
    S: PCS<OC::ScalarField>,
    S::C: CommitmentExt<OC::ScalarField, Affine = OC::Affine>,
    D: DomainSet<OC::ScalarField> + crate::SupportsPackedScheme,
{
    pub fn prove_packed(
        &self,
        bitmask: Bitmask,
    ) -> Result<
        (
            PackedProof<OC::ScalarField, OC::Affine, S::C, S::Proof>,
            AccountablePublicInput<IC>,
        ),
        ApkError,
    > {
        self.prove::<PackedRegisterBuilder<OC::ScalarField, D>>(bitmask)
    }
}

#[cfg(test)]
mod tests {
    use crate::setup::InsecureSetup;
    use crate::test_helpers::random_pks;
    use crate::{
        Apk, ApkConfig, ApkError, Bitmask, Bls12_377Config, Bls12_381Config, CommitmentExt,
        PcsParamsOf, ScalarOf,
    };
    use ark_ec::CurveGroup;
    use ark_std::test_rng;
    use w3f_pcs::pcs::PCS;

    fn check_rejects_bad_bitmasks<C>()
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

        let short = Bitmask::from_bits(&vec![true; n - 1]);
        assert_eq!(
            Apk::<C>::prove(&params, keyset.clone(), &commitment, short).err(),
            Some(ApkError::BitmaskLengthMismatch {
                bitmask: n - 1,
                keyset: n
            })
        );

        let empty = Bitmask::from_bits(&vec![false; n]);
        assert_eq!(
            Apk::<C>::prove(&params, keyset.clone(), &commitment, empty.clone()).err(),
            Some(ApkError::NoSigners)
        );
        assert_eq!(
            Apk::<C>::prove_counting(&params, keyset, &commitment, empty).err(),
            Some(ApkError::NoSigners)
        );
    }

    #[test]
    fn rejects_bad_bitmasks() {
        check_rejects_bad_bitmasks::<Bls12_377Config>();
        check_rejects_bad_bitmasks::<Bls12_381Config>();
    }
}

// use ark_bw6_761::BW6_761;
use ark_ec::{bw6::BW6, CurveGroup};
use ark_poly::{EvaluationDomain, Polynomial};
use fflonk::pcs::kzg::params::KzgCommitterKey;
use fflonk::pcs::kzg::urs::URS;
use fflonk::pcs::{PcsParams, PCS};
use merlin::Transcript;

use crate::domains::Domains;
use crate::keyset::Keyset;
use crate::piop::basic::BasicRegisterBuilder;
use crate::piop::counting::CountingScheme;
use crate::piop::packed::PackedRegisterBuilder;
use crate::piop::ProverProtocol;
use crate::piop::RegisterPolynomials;
use crate::transcript::ApkTranscript;
use crate::{
    AccountablePublicInput, Bitmask, CountingProof, CountingPublicInput, KeysetCommitment,
    NewKzgBw6, PackedProof, Proof, PublicInput, SimpleProof,
};
use crate::{BigCurveCongig, Config377};
pub struct Prover {
    domains: Domains<Config377>,
    keyset: Keyset<BigCurveCongig, Config377>,
    kzg_pk: KzgCommitterKey<ark_ec::bw6::G1Affine<BigCurveCongig>>,
    preprocessed_transcript: Transcript,
}

impl Prover {
    pub fn new(
        mut keyset: Keyset<BigCurveCongig, Config377>,
        keyset_comm: &KeysetCommitment<BigCurveCongig>,
        // prover needs both KZG pk and vk, as it commits to the latter to bind the srs
        kzg_params: URS<BW6<BigCurveCongig>>,
        mut empty_transcript: Transcript,
    ) -> Self {
        let domains = Domains::<Config377>::new(keyset.domain.size());

        // assert!(kzg_params.fits(keyset.domain.size())); // SRS contains enough elements
        empty_transcript.set_protocol_params(&keyset.domain, &kzg_params.raw_vk());
        empty_transcript.set_keyset_commitment(&keyset_comm);

        keyset.amplify();

        Self {
            domains,
            keyset,
            kzg_pk: kzg_params.ck(),
            preprocessed_transcript: empty_transcript,
        }
    }

    pub fn prove_simple(
        &self,
        bitmask: Bitmask,
    ) -> (SimpleProof, AccountablePublicInput<Config377>) {
        self.prove::<BasicRegisterBuilder<Config377>>(bitmask)
    }

    pub fn prove_packed(
        &self,
        bitmask: Bitmask,
    ) -> (PackedProof, AccountablePublicInput<Config377>) {
        self.prove::<PackedRegisterBuilder<Config377>>(bitmask)
    }

    pub fn prove_counting(
        &self,
        bitmask: Bitmask,
    ) -> (CountingProof, CountingPublicInput<Config377>) {
        self.prove::<CountingScheme<Config377>>(bitmask)
    }

    fn prove<P: ProverProtocol>(
        &self,
        bitmask: Bitmask,
    ) -> (
        Proof<P::E, <P::P1 as RegisterPolynomials>::C, <P::P2 as RegisterPolynomials>::C>,
        P::PI,
    ) {
        assert_eq!(bitmask.size(), self.keyset.size());
        assert!(bitmask.count_ones() > 0); // as EC identity doesn't have and affine representation

        let apk = self.keyset.aggregate(&bitmask.to_bits()).into_affine();

        let mut transcript = self.preprocessed_transcript.clone();
        let public_input = P::PI::new(&apk, &bitmask);
        transcript.append_public_input(&public_input);

        // 1. Compute and commit to the basic registers.
        let mut protocol = P::init(self.domains.clone(), bitmask, self.keyset.clone());
        let partial_sums_polynomials = protocol.get_register_polynomials_to_commit1();
        let partial_sums_commitments = partial_sums_polynomials
            .commit(|p| NewKzgBw6::<BigCurveCongig>::commit(&self.kzg_pk, &p).0);

        transcript.append_register_commitments(&partial_sums_commitments);

        // 2. Receive bitmask aggregation challenge,
        // compute and commit to succinct accountability registers.
        let r = transcript.get_bitmask_aggregation_challenge();
        // let acc_registers = D::wrap(registers, b, r);
        let acc_register_polynomials = protocol.get_register_polynomials_to_commit2(r);
        let acc_register_commitments = acc_register_polynomials
            .commit(|p| NewKzgBw6::<BigCurveCongig>::commit(&self.kzg_pk, &p).0);
        transcript.append_2nd_round_register_commitments(&acc_register_commitments);

        // 3. Receive constraint aggregation challenge,
        // compute and commit to the quotient polynomial.
        let phi = transcript.get_constraints_aggregation_challenge();
        let q_poly = protocol.compute_quotient_polynomial(phi, self.keyset.domain);
        let q_comm = NewKzgBw6::<BigCurveCongig>::commit(&self.kzg_pk, &q_poly).0;
        transcript.append_quotient_commitment(&q_comm);

        // 4. Receive the evaluation point,
        // evaluate register polynomials and the quotient polynomial,
        // compute the linearization polynomial and evaluate it at the shifted evaluation point,
        // commit to all the evaluations.
        let zeta = transcript.get_evaluation_point();
        let register_evaluations = protocol.evaluate_register_polynomials(zeta);
        let q_zeta = q_poly.evaluate(&zeta);
        let zeta_omega = zeta * self.keyset.domain.group_gen;
        let r_poly = protocol.compute_linearization_polynomial(phi, zeta);
        let r_zeta_omega = r_poly.evaluate(&zeta_omega);
        transcript.append_evaluations(&register_evaluations, &q_zeta, &r_zeta_omega);

        // 5. Receive the polynomials aggregation challenge,
        // open the aggregated polynomial at the evaluation point,
        // and the linearization polynomial at the shifted evaluation point,
        // and commit to the opening proofs.
        let mut register_polynomials = protocol.get_register_polynomials_to_open();
        register_polynomials.push(q_poly);
        let nus = transcript.get_kzg_aggregation_challenges(register_polynomials.len());
        let w_poly = fflonk::aggregation::single::aggregate_polys(&register_polynomials, &nus);
        let w_at_zeta_proof = NewKzgBw6::<BigCurveCongig>::open(&self.kzg_pk, &w_poly, zeta);
        let r_at_zeta_omega_proof =
            NewKzgBw6::<BigCurveCongig>::open(&self.kzg_pk, &r_poly, zeta_omega);

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

        (proof, public_input)
    }
}

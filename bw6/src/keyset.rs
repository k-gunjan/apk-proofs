use ark_bw6_761::Fr;
use ark_ec::CurveGroup;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain};
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fflonk::pcs::{CommitterKey, PCS};
use fflonk::pcs::kzg::params::KzgCommitterKey;

use crate::{hash_to_curve, NewKzgBw6};
use crate::domains::Domains;

// Polynomial commitment to the vector of public keys.
// Let 'pks' be such a vector that commit(pks) == KeysetCommitment::pks_comm, also let
// domain_size := KeysetCommitment::domain.size and
// keyset_size := KeysetCommitment::keyset_size
// Then the verifier needs to trust that:
// 1. a. pks.len() == KeysetCommitment::domain.size
//    b. pks[i] lie in BLS12-377 G1 for i=0,...,domain_size-2
//    c. for the 'real' keys pks[i], i=0,...,keyset_size-1, there exist proofs of possession
//       for the padding, pks[i], i=keyset_size,...,domain_size-2, dlog is not known,
//       e.g. pks[i] = hash_to_g1("something").
//    pks[domain_size-1] is not a part of the relation (not constrained) and can be anything,
//    we set pks[domain_size-1] = (0,0), not even a curve point.
// 2. KeysetCommitment::domain is the domain used to interpolate pks
//
// In light client protocols the commitment is to the upcoming validator set, signed by the current validator set.
// Honest validator checks the proofs of possession, interpolates with the right padding over the right domain,
// computes the commitment using the right parameters, and then sign it.
// Verifier checks the signatures and can trust that the properties hold under some "2/3 honest validators" assumption.
// As every honest validator generates the same commitment, verifier needs to check only the aggregate signature.
#[derive(Clone, Default, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct KeysetCommitment<OuterCurve>
where
    OuterCurve: Pairing,
{
    /// Per-coordinate KZG commitments to public key polynomials
    pub pks_comm: (OuterCurve::G1Affine, OuterCurve::G1Affine),
    /// Log₂ of the domain size used to interpolate the vectors above.
    pub log_domain_size: u32,
}

type EvaluationsX4<Field> = Evaluations<Field, Radix2EvaluationDomain<Field>>;

#[derive(Clone)]
pub struct Keyset<InnerCurve, OuterCurve>
where
    InnerCurve: Pairing,
    OuterCurve: Pairing,
{
    // Actual public keys, no padding.
    pub pks: Vec<InnerCurve::G1>,
    // Interpolations of the coordinate vectors of the public key vector WITH padding.
    pub pks_polys: [DensePolynomial<OuterCurve::ScalarField>; 2],
    // Domain used to compute the interpolations above.
    pub domain: Radix2EvaluationDomain<OuterCurve::ScalarField>,
    // Polynomials above, evaluated over a 4-times larger domain.
    // Used by the prover to populate the AIR execution trace.
    pub pks_evals_x4: Option<[EvaluationsX4<OuterCurve::ScalarField>; 2]>,
}

impl<InnerCurve, OuterCurve> Keyset<InnerCurve, OuterCurve>
where
    InnerCurve: Pairing,
    OuterCurve: Pairing,
    // TODO: Remove the binding to `ark_bw6_761::G1Affine` and `Fr` after `NewKzgBw6` and domain are made generic
    OuterCurve: Pairing<G1Affine = ark_bw6_761::G1Affine, ScalarField = Fr>,
    // TODO: Remove the binding to Fr after domain is made generic
    InnerCurve::G1Affine: AffineRepr<BaseField = Fr>,
{
    pub fn new(pks: Vec<InnerCurve::G1>) -> Self {
        let min_domain_size = pks.len() + 1; // extra 1 accounts apk accumulator initial value
        let domain: Radix2EvaluationDomain<OuterCurve::ScalarField> =
            Radix2EvaluationDomain::<OuterCurve::ScalarField>::new(min_domain_size)
                .expect("Failed to create evaluation domain");

        let mut padded_pks = pks.clone();
        // a point with unknown discrete log
        let padding_pk = hash_to_curve::<InnerCurve::G1>(b"apk-proofs");
        padded_pks.resize(domain.size(), padding_pk);

        // convert into affine coordinates to commit
        let (pks_x, pks_y): (Vec<OuterCurve::ScalarField>, Vec<OuterCurve::ScalarField>) =
            InnerCurve::G1::normalize_batch(&padded_pks)
                .iter()
                .map(|p: &InnerCurve::G1Affine| p.xy().expect("Invalid point"))
                .unzip();
        let pks_x_poly = Evaluations::from_vec_and_domain(pks_x, domain).interpolate();
        let pks_y_poly = Evaluations::from_vec_and_domain(pks_y, domain).interpolate();
        Self {
            pks,
            domain,
            pks_polys: [pks_x_poly, pks_y_poly],
            pks_evals_x4: None,
        }
    }

    // Actual number of signers, not including the padding
    pub fn size(&self) -> usize {
        self.pks.len()
    }

    pub fn amplify(&mut self) {
        let domains = Domains::new(self.domain.size());
        let pks_evals_x4 = self
            .pks_polys
            .clone()
            .map(|z| domains.amplify_polynomial(&z));
        self.pks_evals_x4 = Some(pks_evals_x4);
    }

    pub fn commit(
        &self,
        kzg_pk: &KzgCommitterKey<OuterCurve::G1Affine>,
    ) -> KeysetCommitment<OuterCurve> {
        assert!(self.domain.size() <= kzg_pk.max_degree() + 1);
        let pks_x_comm = NewKzgBw6::commit(kzg_pk, &self.pks_polys[0]).0;
        let pks_y_comm = NewKzgBw6::commit(kzg_pk, &self.pks_polys[1]).0;
        KeysetCommitment {
            pks_comm: (pks_x_comm, pks_y_comm),
            log_domain_size: self.domain.log_size_of_group,
        }
    }

    pub fn aggregate(&self, bitmask: &[bool]) -> InnerCurve::G1 {
        assert_eq!(bitmask.len(), self.size());
        bitmask
            .iter()
            .zip(self.pks.iter())
            .filter(|(b, _p)| **b)
            .map(|(_b, p)| p)
            .sum()
    }
}

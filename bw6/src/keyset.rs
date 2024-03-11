use std::marker::PhantomData;
use crate::domains::Domains;
use ark_ec::bls12::Bls12Config;
use crate::{hash_to_curve, NewKzgBw6};
use ark_ec::{
    CurveGroup,
    bw6::{BW6Config, G1Affine},
};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fflonk::pcs::kzg::params::KzgCommitterKey;
use fflonk::pcs::{CommitterKey, PCS};
use ark_ec::short_weierstrass::Projective;
pub type G1Projective<P> = Projective<<P as Bls12Config>::G1Config>;
pub type Fr<F> = <F as Bls12Config>::Fp;

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
#[derive(Default, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct KeysetCommitment<Config761: BW6Config> {
    // Per-coordinate KZG commitments to a vector of BLS public keys on BLS12-377 represented in affine.
    pub pks_comm: (G1Affine<Config761>, G1Affine<Config761>),
    // Determines domain used to interpolate the vectors above.
    pub log_domain_size: u32,
}
pub struct Keyset<Config761: BW6Config, CongigBls12: Bls12Config> {
    // Actual public keys, no padding.
    pub pks: Vec<G1Projective<CongigBls12>>,
    // Interpolations of the coordinate vectors of the public key vector WITH padding.
    pub pks_polys: [DensePolynomial<Fr<CongigBls12>>; 2],
    // Domain used to compute the interpolations above.
    pub domain: Radix2EvaluationDomain<Fr<CongigBls12>>,
    // Polynomials above, evaluated over a 4-times larger domain.
    // Used by the prover to populate the AIR execution trace.
    pub pks_evals_x4: Option<[Evaluations<Fr<CongigBls12>, Radix2EvaluationDomain<Fr<CongigBls12>>>; 2]>,
    _marker : PhantomData<Config761>
}

impl<Config761: BW6Config, CongigBls12: Bls12Config<Fp = ark_ff::Fp<MontBackend<ark_bls12_377::FqConfig, 6>, 6>> > Keyset<Config761, CongigBls12> {
    pub fn new(pks: Vec<G1Projective<CongigBls12>>) -> Self {
        let min_domain_size = pks.len() + 1; // extra 1 accounts apk accumulator initial value
        let domain = Radix2EvaluationDomain::<Fr<CongigBls12>>::new(min_domain_size).unwrap();

        let mut padded_pks = pks.clone();
        // a point with unknown discrete log
        let padding_pk = hash_to_curve::<G1Projective<CongigBls12>>(b"apk-proofs");
        padded_pks.resize(domain.size(), padding_pk);

        // convert into affine coordinates to commit
        let (pks_x, pks_y) = G1Projective::<CongigBls12>::normalize_batch(&padded_pks)
            .iter()
            .map(|p| (p.x, p.y))
            .unzip();
        let pks_x_poly = Evaluations::from_vec_and_domain(pks_x, domain).interpolate();
        let pks_y_poly = Evaluations::from_vec_and_domain(pks_y, domain).interpolate();
        Self {
            pks,
            domain,
            pks_polys: [pks_x_poly, pks_y_poly],
            pks_evals_x4: None,
            _marker: Default::default()
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
        kzg_pk: &KzgCommitterKey<G1Affine<Config761>>,
    ) -> KeysetCommitment<Config761> {
        assert!(self.domain.size() <= kzg_pk.max_degree() + 1);
        let pks_x_comm = NewKzgBw6::<Config761>::commit(kzg_pk, &self.pks_polys[0]).0;
        let pks_y_comm = NewKzgBw6::<Config761>::commit(kzg_pk, &self.pks_polys[1]).0;
        KeysetCommitment {
            pks_comm: (pks_x_comm, pks_y_comm),
            log_domain_size: self.domain.log_size_of_group,
        }
    }

    pub fn aggregate(&self, bitmask: &[bool]) -> G1Projective<CongigBls12> {
        assert_eq!(bitmask.len(), self.size());
        bitmask
            .iter()
            .zip(self.pks.iter())
            .filter(|(b, _p)| **b)
            .map(|(_b, p)| p)
            .sum()
    }
}

impl<Config761: BW6Config,  CongigBls12: Bls12Config> Clone for Keyset<Config761, CongigBls12> {
    fn clone(&self) -> Self {
        Keyset {
            pks: self.pks.clone(),
            pks_polys: self.pks_polys.clone(),
            domain: self.domain.clone(),
            pks_evals_x4: self.pks_evals_x4.clone(),
            _marker: Default::default()
        }
    }
}

impl<Config761: BW6Config> Clone for KeysetCommitment<Config761> {
    fn clone(&self) -> Self {
        KeysetCommitment {
            pks_comm: self.pks_comm.clone(),
            log_domain_size: self.log_domain_size,
        }
    }
}

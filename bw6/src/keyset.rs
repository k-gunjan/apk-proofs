use crate::domain::{DomainSet, FftDomain};
use crate::domains::{Domains, Evals};
use crate::hash_to_curve;
use crate::{ApkError, PrimeSubgroup, PublicKeyFault};
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::marker::PhantomData;
use w3f_pcs::pcs::Commitment;
use w3f_pcs::pcs::{CommitterKey, PCS};

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

// The commitment type is generic over different PCS implementations. To extract the
// underlying curve point, go through `CommitmentExt::to_affine` rather than reaching into the
// concrete type: w3f-pcs's KZG, for instance, wraps the point as
// `pub struct WrappedAffine<C: CurveGroup>(pub C::Affine)`, but nothing here should depend on
// that.
#[derive(Clone, Default, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct KeysetCommitment<F, C>
where
    F: PrimeField,
    C: Commitment<F>,
{
    /// Per-coordinate commitments to public key polynomials
    pub pks_comm: (C, C),
    /// Size of the domain used to interpolate the vectors above.
    pub domain_size: u64,
    _m: PhantomData<F>,
}

#[derive(Clone)]
pub struct Keyset<IC, OC, D>
where
    IC: CurveGroup,
    OC: CurveGroup,
    // OC::ScalarField: From<IC::BaseField>,
    D: DomainSet<OC::ScalarField>,
{
    // Actual public keys, no padding.
    pub(crate) pks: Vec<IC>,
    // Interpolations of the coordinate vectors of the public key vector WITH padding.
    pub(crate) pks_polys: [DensePolynomial<OC::ScalarField>; 2],
    // The domains used to compute the interpolations above, and to expand them.
    pub(crate) domains: D,
    // Polynomials above, evaluated over at a domain of size at least (4n-2).
    // Used by the prover to populate the AIR execution trace.
    pub(crate) pks_evals_x4: Option<[Evals<OC::ScalarField>; 2]>,
}

impl<IC, OC, D> Keyset<IC, OC, D>
where
    IC: CurveGroup,
    OC: CurveGroup,
    OC::ScalarField: From<IC::BaseField>,
    D: DomainSet<OC::ScalarField>,
{
    /// Pads and interpolates a signer set.
    ///
    /// The keys typically come from the chain, so they are checked: each must be a non-identity
    /// point of the prime-order subgroup G1. The check costs about a scalar multiplication per
    /// key, paid once per validator set rather than once per proof.
    pub fn new(pks: Vec<IC>) -> Result<Self, ApkError>
    where
        IC: PrimeSubgroup,
    {
        let min_domain_size = pks.len() + 1; // extra 1 accounts apk accumulator initial value
        // Before key validation: this is a lookup, validation is per key.
        let domains = D::for_min_size(min_domain_size)?;
        let domain = domains.base();

        let mut padded_pks = pks.clone();
        // a point with unknown discrete log
        let padding_pk = hash_to_curve::<IC>(b"apk-proofs");
        padded_pks.resize(domain.size(), padding_pk);

        // convert into affine coordinates to commit
        let affine_pks = IC::normalize_batch(&padded_pks);
        for (index, pk) in affine_pks[..pks.len()].iter().enumerate() {
            let fault = if pk.is_zero() {
                PublicKeyFault::Identity
            } else if !IC::is_in_prime_subgroup(pk) {
                PublicKeyFault::NotInSubgroup
            } else {
                continue;
            };
            return Err(ApkError::InvalidPublicKey { index, fault });
        }

        let mut pks_x = Vec::with_capacity(affine_pks.len());
        let mut pks_y = Vec::with_capacity(affine_pks.len());
        for affine_point in &affine_pks {
            let (x, y) = affine_point
                .xy()
                .expect("invariant: real keys were checked above, padding is a random G1 element");
            pks_x.push((x).into());
            pks_y.push((y).into());
        }
        let pks_x_poly = DensePolynomial::from_coefficients_vec(domain.interpolate(&pks_x));
        let pks_y_poly = DensePolynomial::from_coefficients_vec(domain.interpolate(&pks_y));
        Ok(Self {
            pks,
            domains,
            pks_polys: [pks_x_poly, pks_y_poly],
            pks_evals_x4: None,
        })
    }

    /// The public keys, without padding.
    pub fn pks(&self) -> &[IC] {
        &self.pks
    }

    // Actual number of signers, not including the padding
    pub fn size(&self) -> usize {
        self.pks.len()
    }

    /// The trace domain the public keys were interpolated over.
    pub fn domain(&self) -> &D::Domain {
        self.domains.base()
    }

    pub fn amplify(&mut self) {
        let domains = Domains::<OC::ScalarField, D>::from_set(self.domains.clone());
        let pks_evals_x4 = self
            .pks_polys
            .clone()
            .map(|z| domains.amplify_polynomial(&z));
        self.pks_evals_x4 = Some(pks_evals_x4);
    }

    pub fn commit<S>(
        &self,
        committer_key: &S::CK,
    ) -> Result<KeysetCommitment<OC::ScalarField, S::C>, ApkError>
    where
        S: PCS<OC::ScalarField>,
    {
        let domain_size = self.domain().size();
        // The keyset polynomials have degree `n - 1`.
        if domain_size > committer_key.max_degree() + 1 {
            return Err(ApkError::SrsTooSmall {
                domain_size,
                required_degree: domain_size - 1,
                available_degree: committer_key.max_degree(),
            });
        }
        let pks_x_comm = S::commit(committer_key, &self.pks_polys[0])
            .map_err(|_| ApkError::Pcs("commit to keyset x-coordinates"))?;
        let pks_y_comm = S::commit(committer_key, &self.pks_polys[1])
            .map_err(|_| ApkError::Pcs("commit to keyset y-coordinates"))?;
        Ok(KeysetCommitment {
            pks_comm: (pks_x_comm, pks_y_comm),
            domain_size: domain_size as u64,
            _m: PhantomData::default(),
        })
    }

    pub fn aggregate(&self, bitmask: &[bool]) -> Result<IC, ApkError> {
        if bitmask.len() != self.size() {
            return Err(ApkError::BitmaskLengthMismatch {
                bitmask: bitmask.len(),
                keyset: self.size(),
            });
        }
        Ok(bitmask
            .iter()
            .zip(self.pks.iter())
            .filter(|(b, _p)| **b)
            .map(|(_b, p)| p)
            .sum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::InsecureSetup;
    use crate::test_helpers::random_pks;
    use crate::{Apk, ApkConfig, Bls12_377Config, Bls12_381Config, KeysetOf, PcsParamsOf, ScalarOf};
    use ark_ec::short_weierstrass::SWCurveConfig;
    use ark_std::{test_rng, Zero};
    use w3f_pcs::pcs::{PcsParams, PCS};

    fn check_rejects_bad_keys<C, P>()
    where
        C: ApkConfig,
        C::InnerCurve: From<ark_ec::short_weierstrass::Affine<P>>,
        P: SWCurveConfig,
        ScalarOf<C>: From<<C::InnerCurve as CurveGroup>::BaseField>,
    {
        let rng = &mut test_rng();

        let mut pks = random_pks::<_, C::InnerCurve>(10, rng);
        pks[3] = C::InnerCurve::zero();
        assert_eq!(
            KeysetOf::<C>::new(pks).err(),
            Some(ApkError::InvalidPublicKey {
                index: 3,
                fault: PublicKeyFault::Identity
            })
        );

        // On the curve, but of order 3: the accumulator seed itself is such a point.
        let mut pks = random_pks::<_, C::InnerCurve>(10, rng);
        pks[5] = crate::point_in_g1_complement::<P>().into();
        assert_eq!(
            KeysetOf::<C>::new(pks).err(),
            Some(ApkError::InvalidPublicKey {
                index: 5,
                fault: PublicKeyFault::NotInSubgroup
            })
        );
    }

    #[test]
    fn rejects_identity_and_non_subgroup_keys() {
        check_rejects_bad_keys::<Bls12_377Config, ark_bls12_377::g1::Config>();
        check_rejects_bad_keys::<Bls12_381Config, ark_bls12_381::g1::Config>();
    }

    fn check_commit_reports_small_srs<C>()
    where
        C: ApkConfig,
        ScalarOf<C>: From<<C::InnerCurve as CurveGroup>::BaseField> + ark_ff::FftField,
        <C::Pcs as PCS<ScalarOf<C>>>::C: crate::CommitmentExt<
                ScalarOf<C>,
                Affine = <C::OuterCurve as CurveGroup>::Affine,
            > + Clone,
        PcsParamsOf<C>: Clone,
        InsecureSetup: crate::setup::PcsSetup<ScalarOf<C>, C::Pcs>,
    {
        let rng = &mut test_rng();
        // Parameters for 2 keys, a keyset of 100.
        let params = Apk::<C>::setup(&mut InsecureSetup::new(rng), 2).unwrap();
        let keyset = KeysetOf::<C>::new(random_pks(100, rng)).unwrap();
        match keyset.commit::<C::Pcs>(&params.ck()) {
            Err(ApkError::SrsTooSmall { domain_size, .. }) => {
                assert_eq!(domain_size, keyset.domain().size())
            }
            other => panic!("expected SrsTooSmall, got {:?}", other.err()),
        }
    }

    #[test]
    fn commit_reports_small_srs() {
        check_commit_reports_small_srs::<Bls12_377Config>();
        check_commit_reports_small_srs::<Bls12_381Config>();
    }

    #[test]
    fn aggregate_rejects_bitmask_of_wrong_length() {
        let rng = &mut test_rng();
        let keyset = KeysetOf::<Bls12_381Config>::new(random_pks(10, rng)).unwrap();
        assert_eq!(
            keyset.aggregate(&[true; 9]).err(),
            Some(ApkError::BitmaskLengthMismatch {
                bitmask: 9,
                keyset: 10
            })
        );
    }
}

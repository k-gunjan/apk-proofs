use std::marker::PhantomData;

use crate::Fr as FrG;
use ark_ec::bls12::Bls12Config;
type Fr = FrG<Config377>;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::domains::Domains;
use crate::piop::affine_addition::{
    AffineAdditionEvaluations, AffineAdditionRegisters, PartialSumsPolynomials,
};
use crate::piop::{ProverProtocol, RegisterEvaluations};
use crate::{utils, AccountablePublicInput, Bitmask, Keyset};
use crate::{BigCurveCongig, Config377};
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct AffineAdditionEvaluationsWithoutBitmask {
    pub keyset: (Fr, Fr),
    pub partial_sums: (Fr, Fr),
}

impl RegisterEvaluations for AffineAdditionEvaluationsWithoutBitmask {
    fn as_vec(&self) -> Vec<Fr> {
        vec![
            self.keyset.0,
            self.keyset.1,
            self.partial_sums.0,
            self.partial_sums.1,
        ]
    }
}

pub struct BasicRegisterBuilder<ConfigBls12: Bls12Config> {
    registers: AffineAdditionRegisters,
    register_evaluations: Option<AffineAdditionEvaluations>,
    _marker: PhantomData<ConfigBls12>,
}

impl<ConfigBls12: Bls12Config> ProverProtocol for BasicRegisterBuilder<ConfigBls12> {
    type P1 = PartialSumsPolynomials;
    type P2 = ();
    type E = AffineAdditionEvaluationsWithoutBitmask;
    type PI = AccountablePublicInput<ConfigBls12>;

    fn init(
        domains: Domains<Config377>,
        bitmask: Bitmask,
        keyset: Keyset<BigCurveCongig, Config377>,
    ) -> Self {
        BasicRegisterBuilder {
            registers: AffineAdditionRegisters::new(domains, keyset, &bitmask.to_bits()),
            register_evaluations: None,
            _marker: Default::default(),
        }
    }

    fn get_register_polynomials_to_commit1(&self) -> PartialSumsPolynomials {
        let polys = self.registers.get_register_polynomials();
        polys.partial_sums
    }

    fn get_register_polynomials_to_commit2(&mut self, _verifier_challenge: Fr) -> () {
        ()
    }

    fn get_register_polynomials_to_open(self) -> Vec<DensePolynomial<Fr>> {
        let polys = self.registers.get_register_polynomials();
        [polys.keyset, polys.partial_sums].concat()
    }

    fn compute_constraint_polynomials(&self) -> Vec<DensePolynomial<Fr>> {
        self.registers.compute_constraint_polynomials()
    }

    // bitmask register polynomial is not committed to...
    fn evaluate_register_polynomials(
        &mut self,
        point: Fr,
    ) -> AffineAdditionEvaluationsWithoutBitmask {
        let evals: AffineAdditionEvaluations = self.registers.evaluate_register_polynomials(point);
        self.register_evaluations = Some(evals.clone());
        AffineAdditionEvaluationsWithoutBitmask {
            keyset: evals.keyset,
            partial_sums: evals.partial_sums,
        }
    }

    fn compute_linearization_polynomial(&self, phi: Fr, zeta: Fr) -> DensePolynomial<Fr> {
        let evals = self.register_evaluations.as_ref().unwrap();
        let parts = self.registers.compute_constraints_linearized(evals, zeta);
        utils::randomize(phi, &parts)
    }
}

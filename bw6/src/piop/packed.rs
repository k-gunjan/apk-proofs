use crate::constraints::{SuccinctlyAccountableRegisters, SuccinctAccountableRegisterEvaluations};
use crate::piop::{Protocol, RegisterPolys, PackedAccountabilityRegisterPolynomials};
use crate::domains::Domains;
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_bls12_377::{G1Affine, Fq};
use crate::Bitmask;
use ark_bw6_761::Fr;
use crate::piop::affine_addition::{AffineAdditionRegisters, PartialSumsPolynomials};

pub struct PackedRegisterBuilder {
    affine_addition_registers: AffineAdditionRegisters,
    bitmask_packing_registers: Option<SuccinctlyAccountableRegisters>,
}

impl Protocol<SuccinctAccountableRegisterEvaluations> for PackedRegisterBuilder {
    type P1 = PartialSumsPolynomials;
    type P2 = PackedAccountabilityRegisterPolynomials;

    fn init(domains: Domains, bitmask: &Bitmask, pks: Vec<G1Affine>) -> Self {
        PackedRegisterBuilder {
            affine_addition_registers: AffineAdditionRegisters::new(domains, bitmask, pks),
            bitmask_packing_registers: None
        }
    }

    fn get_1st_round_register_polynomials(&self) -> Self::P1 {
        self.affine_addition_registers.get_1st_round_register_polynomials()
    }

    fn get_2nd_round_register_polynomials(&mut self, bitmask: Vec<Fr>, bitmask_chunks_aggregation_challenge: Fr) -> Self::P2 {
        let bitmask_packing_registers = SuccinctlyAccountableRegisters::new(
            self.affine_addition_registers.clone(),
            bitmask,
            bitmask_chunks_aggregation_challenge
        );
        let res = PackedAccountabilityRegisterPolynomials::new(
            bitmask_packing_registers.polynomials.c_poly.clone(),
            bitmask_packing_registers.polynomials.acc_poly.clone(),
        );
        *self = PackedRegisterBuilder {
            affine_addition_registers: self.affine_addition_registers.clone(),
            bitmask_packing_registers: Some(bitmask_packing_registers)
        };
        res
    }

    fn evaluate_register_polynomials(&self, point: Fq) -> SuccinctAccountableRegisterEvaluations {
        self.bitmask_packing_registers.as_ref().unwrap().evaluate_register_polynomials(point)
    }

    fn compute_linearization_polynomial(&self, evaluations: &SuccinctAccountableRegisterEvaluations, phi: Fq, zeta_minus_omega_inv: Fq) -> DensePolynomial<Fq> {
        self.bitmask_packing_registers.as_ref().unwrap().compute_linearization_polynomial(evaluations, phi, zeta_minus_omega_inv)
    }

    fn compute_constraint_polynomials(&self) -> Vec<DensePolynomial<Fq>> {
        self.bitmask_packing_registers.as_ref().unwrap().compute_constraint_polynomials()
    }

    fn get_all_register_polynomials(self) -> Vec<DensePolynomial<Fq>> {
        self.bitmask_packing_registers.unwrap().get_all_register_polynomials()
    }
}
use ark_ff::PrimeField;
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial,
};

/// A multiplicative evaluation domain: a subgroup `H = <w>` of `F*` of order `n`, together with
/// forward and inverse transforms between coefficient and evaluation form.
///
/// This exists because the two APK configurations cannot share an FFT strategy. BW6-761's scalar
/// field has two-adicity 46, so radix-2 works for any power-of-two size. BW6-767's has two-adicity
/// **1**: no power-of-two domain beyond size 2 exists there, and no domain whose size is divisible
/// by 4 exists at all. Sizes there are divisors of `2 * 3^2 * 11 * 23 * 47 * 10177`, transformed
/// with mixed-radix Cooley-Tukey (and Rader for the 10177 factor).
///
/// Implementations must return evaluations in natural order, i.e. index `i` holds the value at
/// `w^i`. Several callers depend on that ordering.
pub trait FftDomain<F: PrimeField>: Clone + Sized {
    /// Domain size `n`.
    fn size(&self) -> usize;

    /// The generator `w`, a primitive `n`-th root of unity.
    fn generator(&self) -> F;

    /// `w^{-1}`.
    fn generator_inv(&self) -> F;

    /// `n^{-1}`, used to normalise the inverse transform.
    fn size_inv(&self) -> F;

    /// Coefficients -> evaluations at `(1, w, ..., w^{n-1})`.
    fn fft(&self, coeffs: &[F]) -> Vec<F>;

    /// Evaluations -> coefficients. Exact only when the underlying polynomial has degree `< n`;
    /// otherwise the result is the polynomial reduced modulo `X^n - 1`.
    fn interpolate(&self, evals: &[F]) -> Vec<F>;

    /// The `i`-th domain element, `w^i`.
    fn element(&self, i: usize) -> F {
        self.generator().pow([i as u64])
    }

    /// `Z_H(x) = x^n - 1`.
    ///
    /// Generic exponentiation rather than a chain of squarings: `n` is not a power of two in
    /// general.
    fn evaluate_vanishing_polynomial(&self, x: F) -> F {
        x.pow([self.size() as u64]) - F::one()
    }

    /// Divides by `Z_H(X) = X^n - 1`, returning `(quotient, remainder)`.
    ///
    /// Done in coefficient form rather than pointwise over a coset, which keeps this correct
    /// whether or not `H` is contained in the larger evaluation domain.
    fn divide_by_vanishing_poly(
        &self,
        poly: &DensePolynomial<F>,
    ) -> (DensePolynomial<F>, DensePolynomial<F>) {
        let mut vanishing_coeffs = vec![F::zero(); self.size() + 1];
        vanishing_coeffs[0] = -F::one();
        vanishing_coeffs[self.size()] = F::one();
        let vanishing_poly = DensePolynomial::from_coefficients_vec(vanishing_coeffs);

        let a = DenseOrSparsePolynomial::from(poly);
        let b = DenseOrSparsePolynomial::from(&vanishing_poly);
        a.divide_with_q_and_r(&b)
            .expect("division by the vanishing polynomial failed")
    }

    /// All Lagrange basis polynomials evaluated at `x`:
    /// `L_i(x) = (x^n - 1) / (n * (x - w^i)) * w^i`.
    fn evaluate_all_lagrange_coefficients(&self, x: F) -> Vec<F> {
        let n = self.size();
        let vanishing_scaled = self.evaluate_vanishing_polynomial(x) * self.size_inv();

        let mut denominators = Vec::with_capacity(n);
        let mut power = F::one();
        for _ in 0..n {
            denominators.push(x - power);
            power *= self.generator();
        }
        ark_ff::batch_inversion(&mut denominators);

        let mut result = Vec::with_capacity(n);
        power = F::one();
        for denom_inv in denominators {
            result.push(vanishing_scaled * denom_inv * power);
            power *= self.generator();
        }
        result
    }
}

/// Constructs a domain of at least the requested size.
///
/// The size is rounded **up** to the next size the field actually supports, so callers must read
/// back `size()` rather than assuming they got what they asked for.
///
/// `F` is a type parameter rather than an associated type on purpose: as an associated type it
/// forces every bound to be spelled `D: FftDomain<F> + DomainFactory<Field = F>`, which is both
/// noisy and easy to get wrong.
pub trait DomainFactory<F: PrimeField>: FftDomain<F> {
    fn create_domain(size: usize) -> Self;
}

/// Marks domains that can supply the sizes the `packed` scheme needs.
///
/// `packed` splits the bitmask into 256-bit chunks and asserts `256 | n`. Only a radix-2 domain
/// can guarantee that. Over BW6-767 it is outright impossible: `q - 1` carries a single factor
/// of 2, so no domain size there is even a multiple of 4, let alone 256.
///
/// This is a marker rather than a runtime check so that asking for a packed proof on a
/// configuration that cannot produce one fails to compile, instead of panicking inside the
/// prover after the caller has already built a keyset.
pub trait SupportsPackedScheme {}

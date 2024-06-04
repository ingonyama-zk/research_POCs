use icicle_core::{
    curve::{self, Curve}, field::Field, msm::{MSMConfig, MSM}, ntt::{get_root_of_unity, initialize_domain}, 
    polynomials::UnivariatePolynomial, traits::{FieldConfig, FieldImpl, GenerateRandom}, 
    vec_ops::{add_scalars, mul_scalars, sub_scalars, transpose_matrix, VecOpsConfig}
    };

use icicle_cuda_runtime::{
    device_context::DeviceContext,
    memory::{DeviceVec, HostSlice},
};


use icicle_bn254::{
    curve::{ScalarField as bn254Scalar,BaseField as bn254Points},
    polynomials::DensePolynomial as PolynomialBn254};

use icicle_babybear::{field::ScalarField as babybearScalar,
    polynomials::DensePolynomial as PolynomialBabyBear};




pub fn init_bn254(max_ntt_size: u64) {
    // initialize NTT domain for all fields!. Polynomials ops relies on NTT
    let rou_bn254: bn254Scalar = get_root_of_unity(max_ntt_size);    
    let ctx = DeviceContext::default();
    initialize_domain(rou_bn254, &ctx, false /*=fast twiddles mode*/).unwrap();
    // initialize the cuda backend for polynomials (per field)
    PolynomialBn254::init_cuda_backend();
}

pub fn init_babybear(max_ntt_size: u64) {
    // initialize NTT domain for all fields!. Polynomials ops relies on NTT
    let rou_babybear: babybearScalar = get_root_of_unity(max_ntt_size);    
    let ctx = DeviceContext::default();
    initialize_domain(rou_babybear, &ctx, false /*=fast twiddles mode*/).unwrap();
    // initialize the cuda backend for polynomials (per field)
    PolynomialBabyBear::init_cuda_backend();
}

pub fn randomize_poly<P>(size: usize, from_coeffs: bool) -> P
where
    P: UnivariatePolynomial,
    P::Field: FieldImpl,
    P::FieldConfig: GenerateRandom<P::Field>,
{
    let coeffs_or_evals = P::FieldConfig::generate_random(size);
    let p = if from_coeffs {
        P::from_coeffs(HostSlice::from_slice(&coeffs_or_evals), size)
    } else {
        P::from_rou_evals(HostSlice::from_slice(&coeffs_or_evals), size)
    };
    p
}

/// this function takes two univariate polynomials and checks that they are the equal. 
pub fn assert_poly_eq<P:UnivariatePolynomial>(
    poly1: P,
    poly2: P,
) {
    assert_eq!(poly1.degree(),poly2.degree(),"Polynomials must be of same length!");
    let deg:u64 = poly1.degree().try_into().unwrap();
    for _i in 0..=deg {
            assert_eq!(poly1.get_coeff(_i),poly2.get_coeff(_i),"Polynomials are not equal!");
    }
}








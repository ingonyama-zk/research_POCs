use std::cmp::max;

use icicle_core::{
    bignum::BigNum, field::Field, 
    ntt::{get_root_of_unity, initialize_domain, NTTDomain,NTTInitDomainConfig}, 
    polynomials::UnivariatePolynomial, traits::{Arithmetic, GenerateRandom, Invertible}
};

use icicle_runtime::memory::HostSlice;

use icicle_bn254::{curve::ScalarField as Fr, polynomials::DensePolynomial};

pub fn generate_random_poly<P>(size: usize, from_coeffs: bool) -> P
where
    P: UnivariatePolynomial,
    P::Coeff: Arithmetic+BigNum+Field+GenerateRandom,
{
    println!(
        "Randomizing polynomial of size {} (from_coeffs: {})",
        size, from_coeffs
    );
    let coeffs_or_evals = P::Coeff::generate_random(size);
    let p = if from_coeffs {
        P::from_coeffs(HostSlice::from_slice(&coeffs_or_evals), size)
    } else {
        P::from_rou_evals(HostSlice::from_slice(&coeffs_or_evals), size)
    };
    p
}

pub fn init_ntt_domain<F>(max_ntt_size: u64)
where
    F: Arithmetic+Field+BigNum+NTTDomain<F>,
{
    // Initialize NTT domain for all fields. Polynomial operations rely on NTT.
    println!(
        "Initializing NTT domain for max size 2^{}",
        max_ntt_size.trailing_zeros()
    );
    //test will fail when coset gen !=1
    let rou: F = get_root_of_unity::<F>(max_ntt_size).unwrap();
    //test fails for coset gen!=1 since init domain doesnt accept order of primitive root !=2
    initialize_domain(rou, &NTTInitDomainConfig::default()).unwrap();
}

fn main() {
    //deg d1,d2 1<<6=32
    let size:usize = 33;
    //product poly deg d1+d2 = 1<<7
    //max domain ssize should be >= 1<<7
    let max_domain_size:u64= 1<<7;

    init_ntt_domain::<Fr>(max_domain_size);
    let p1 = generate_random_poly::<DensePolynomial>(size, true);
    println!("p1:degree {:?}", p1.degree());
    let p2 = generate_random_poly::<DensePolynomial>(size, true);
    println!("p2:degree {:?}", p2.degree());
    //max domain size should be assigned  as per expected polynomal degree encountered
    //Safe to set to max size possible
    let result = p1.mul(&p2);
    println!("result:degree {:?}", result.degree());
    println!("p1 evals size {:?}", p1.get_nof_coeffs());
    println!("p2 evals size {:?}", p2.get_nof_coeffs());     
    assert_eq!(p1.degree()+p2.degree(), result.degree());
}
use rust::*;

use icicle_core::{
    curve::Curve, field::Field,impl_scalar_field,msm::{MSMConfig, MSM}, 
    ntt::{get_root_of_unity, initialize_domain,NTTConfig}, 
    polynomials::UnivariatePolynomial, 
    traits::{GenerateRandom,FieldImpl}, 
    vec_ops::{add_scalars, mul_scalars, sub_scalars, VecOpsConfig}
    };

    use icicle_cuda_runtime::{ 
        device_context::DeviceContext,
        memory::{DeviceVec, HostSlice},
    };

use icicle_bn254::{
        curve::{BaseField as bn254Points, ScalarCfg, ScalarField as bn254Scalar},
        polynomials::DensePolynomial as PolynomialBn254, vec_ops,tree};

use icicle_babybear::{field::ScalarField as babybearScalar,
            polynomials::DensePolynomial as PolynomialBabyBear};

#[cfg(feature = "profile")]
use std::time::Instant;
use clap::Parser;
#[derive(Parser, Debug)]
pub struct Args {
            /// Size of NTT to run (20 for 2^20)
            #[arg(short, long, default_value_t = 20)]
            max_ntt_log_size: u8,
            #[arg(short, long, default_value_t = 15)]
            poly_log_size: u8,
        }

pub fn main() {
    let args = Args::parse();
    init_bn254(1 << args.max_ntt_log_size);
    let poly_size = 1 << args.poly_log_size;
    simple_identity(poly_size);
}
pub fn simple_identity(poly_size:usize){
    let f1 = randomize_poly::<PolynomialBn254>(poly_size, true /*from random coeffs*/);
    let f2 = randomize_poly::<PolynomialBn254>(poly_size, true /*from random coeffs*/);
    let add = &f1+&f2;
    let sub = &f1-&f2;
    let lhs = &(&add*&add) - &(&sub*&sub);
    let rhs = &(&f1*&f2)* &bn254Scalar::from_u32(4);
    assert_poly_eq(lhs,rhs); 
    println!("Tested (f1+f2)^2-(f1-f2)^2 == 4 f_1 f_2 for f_1,f_2 deg {:?}", poly_size);
    let l1 = &(&add*&add) + &(&sub*&sub);
    let r1 = &(&(&f1*&f1) + &(&f2*&f2)) * &bn254Scalar::from_u32(2);
    assert_poly_eq(l1,r1); 
    println!("Tested (f1+f2)^2+(f1-f2)^2 == 2 (f_1^2+ f_2^2) for f_1,f_2 deg {:?}",poly_size);
}
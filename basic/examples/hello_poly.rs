use rand::random;

use icicle_bn254::{curve::ScalarField as Fr, polynomials::DensePolynomial as polybn254};

use icicle_core::{
    ntt::{get_root_of_unity, initialize_domain, NTTInitDomainConfig},
    polynomials::UnivariatePolynomial,
    traits::{FieldImpl, GenerateRandom}};
use icicle_runtime::memory::HostSlice;
use icicle_runtime::{self, Device};
use basic::utils::*;



fn ptest1<P: UnivariatePolynomial>(
    p1: P,
    p2: P,
    alpha: P::Field,
) -> (P::Field, P::Field, P::Field, P::Field) {
    let ta: P = p1.add(&p2);
    let ts: P = p1.sub(&p2);
    let tAsq = ta.mul(&ta);
    let tssq = ts.mul(&ts);
    let t1_l = tAsq.add(&tssq);
    let t2_l = tAsq.sub(&tssq);
    let two = <P::Field as FieldImpl>::from_u32(2);
    let four = <P::Field as FieldImpl>::from_u32(4);
    let t1_r = p1.mul(&p1).add(&p2.mul(&p2)).mul_by_scalar(&two);
    let t2_r = p1.mul(&p2).mul_by_scalar(&four);
    (
        t1_l.eval(&alpha),
        t1_r.eval(&alpha),
        t2_l.eval(&alpha),
        t2_r.eval(&alpha),
    )
}


// cargo run --release --package basic --example hello_poly
fn main() {
    try_load_and_set_backend_metal();
    let size: usize = 1024;
    println!("Polynomial log_degree size: {:?}", 10);
    println!("Identity checking: (p1+p2)^2+(p1-p2)^2 =? 2 (p_1^2+p_2^2)");
    println!("Identity checking: (p1+p2)^2-(p1-p2)^2 =? 4 p_1.p_2");
    let logsize = 14;
    println!("max_domain size needed: {:?}", logsize);
    // let device = icicle_runtime::Device::new(&args.device_type, 0 /* =device_id*/);
    init_ntt_domain(1 << logsize);

    let size: usize = 1024;
    let size: usize = 1024;

    let two = Fr::from_u32(2);
    let one = Fr::from_u32(1);
    let four = Fr::from_u32(4);
    let alpha = Fr::from_u32(random::<u32>());
    let two = Fr::from_u32(2);
    let one = Fr::from_u32(1);
    let four = Fr::from_u32(4);
    let alpha = Fr::from_u32(random::<u32>());

    let v1 = <Fr as FieldImpl>::Config::generate_random(size);
    let v2 = <Fr as FieldImpl>::Config::generate_random(size);
    let v1 = <Fr as FieldImpl>::Config::generate_random(size);
    let v2 = <Fr as FieldImpl>::Config::generate_random(size);

    let p1 = polybn254::from_rou_evals(HostSlice::from_slice(&v1), size);
    let p2 = polybn254::from_rou_evals(HostSlice::from_slice(&v2), size);
    let (a1, a2, a3, a4) = ptest1(p1.clone(), p2.clone(), alpha);
    // //(p1+p2)^2
    let tA = &(&p1 + &p2) * &(&p1 + &p2);
    // //(p1-p2)^2
    let tB = &(&p1 - &p2) * &(&p1 - &p2);
    // //(p1+p2)^2+(p1-p2)^2
    let t1_l = &tA + &tB;
    // //(p1+p2)^2-(p1-p2)^2
    let t2_l = &tA - &tB;
    // //  2(p_1^2+p_2^2)
    let t1_r = &(&(&p1 * &p1) + &(&p2 * &p2)) * &two;
    // //  4(p_1 p_2)
    let t2_r = &(&p1 * &p2) * &four;

    // chec
    println!("Check Schwarz Zippel at random x = {:?}", alpha);
    let t1_l_one = t1_l.eval(&alpha);
    let t1_r_one = t1_r.eval(&alpha);
    let t2_l_one = t2_l.eval(&alpha);
    let t2_r_one = t2_r.eval(&alpha);
    assert_eq!(t1_l_one, t1_r_one);
    assert_eq!(a1, a2);
    assert_eq!(t1_l_one, a1);
    println!(
        "(p_1(x)+p_2(x))^2+(p_1(x)-p_2(x))^2 eval at x: {:?}, from generic {:?}",
        t1_l_one, a1
    );
    println!(
        "2 (p_1(x)^2+p_2(x)^2 eval at x: {:?}, from generic {:?}",
        t1_r_one, a2
    );
    assert_eq!(t2_l_one, t2_r_one);
    assert_eq!(a3, a4);
    assert_eq!(t2_l_one, a3);

    println!(
        "(p_1(x)+p_2(x))^2-(p_1(x)-p_2(x))^2 eval at x: {:?}, from generic {:?}",
        t2_l_one, a3
    );
    println!(
        "4 p_1(x)*p_2(x) eval at x: is {:?},from generic {:?}",
        t2_r_one, a4
    );
}


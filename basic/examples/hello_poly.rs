use rand::random;

use icicle_bn254::{curve::ScalarField as Fr, polynomials::DensePolynomial as polybn254};

use icicle_core::{
    ntt::{get_root_of_unity, initialize_domain, NTTInitDomainConfig},
    polynomials::UnivariatePolynomial,
    traits::{FieldImpl, GenerateRandom},
    ntt::{get_root_of_unity, initialize_domain, NTTInitDomainConfig},
    polynomials::UnivariatePolynomial,
    traits::{FieldImpl, GenerateRandom},
};
use icicle_runtime::memory::HostSlice;
use icicle_runtime::{self, Device};

fn init_ntt_domain(max_ntt_size: u64) {
    // Initialize NTT domain for all fields. Polynomial operations rely on NTT.
    println!(
        "Initializing NTT domain for max size 2^{}",
        max_ntt_size.trailing_zeros()
    );
    let rou_bn254: Fr = get_root_of_unity(max_ntt_size);
    initialize_domain(rou_bn254, &NTTInitDomainConfig::default()).unwrap();
}

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

fn main() {
    icicle_runtime::load_backend("../cuda_backend/icicle/lib/backend").unwrap();
    let _ = icicle_runtime::load_backend_from_env_or_default();

    // Check if GPU is available
    let device_cpu = Device::new("CPU", 0);
    let mut device_gpu = Device::new("CUDA", 0);
    let is_cuda_device_available = icicle_runtime::is_device_available(&device_gpu);
    // Check if GPU is available
    let device_cpu = Device::new("CPU", 0);
    let mut device_gpu = Device::new("CUDA", 0);
    let is_cuda_device_available = icicle_runtime::is_device_available(&device_gpu);

    if is_cuda_device_available {
        println!("GPU is available");
    } else {
        println!("GPU is not available, falling back to CPU only");
        device_gpu = device_cpu.clone();
    }

    let size: usize = 1024;
    println!("Polynomial log_degree size: {:?}", 10);
    println!("Identity checking: (p1+p2)^2+(p1-p2)^2 =? 2 (p_1^2+p_2^2)");
    println!("Identity checking: (p1+p2)^2-(p1-p2)^2 =? 4 p_1.p_2");
    let logsize = 14;
    println!("max_domain size needed: {:?}", logsize);
    // let device = icicle_runtime::Device::new(&args.device_type, 0 /* =device_id*/);
    icicle_runtime::set_device(&device_gpu).unwrap();
    init_ntt_domain(1 << logsize);
    let size: usize = 1024;
    println!("Polynomial log_degree size: {:?}", 10);
    println!("Identity checking: (p1+p2)^2+(p1-p2)^2 =? 2 (p_1^2+p_2^2)");
    println!("Identity checking: (p1+p2)^2-(p1-p2)^2 =? 4 p_1.p_2");
    let logsize = 14;
    println!("max_domain size needed: {:?}", logsize);
    // let device = icicle_runtime::Device::new(&args.device_type, 0 /* =device_id*/);
    icicle_runtime::set_device(&device_gpu).unwrap();
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


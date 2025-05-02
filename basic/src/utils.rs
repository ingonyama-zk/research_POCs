use icicle_runtime::{runtime, Device};

use icicle_core::{
    ntt::{get_root_of_unity, initialize_domain, NTTInitDomainConfig}};
use icicle_bn254::{curve::ScalarField as Fr, polynomials::DensePolynomial as polybn254};

pub fn set_backend_cpu() {
    
    let device_cpu = Device::new("CPU", 0);
    icicle_runtime::set_device(&device_cpu).unwrap();
}

pub fn try_load_and_set_backend_metal() {
    runtime::load_backend("../metal_backend/icicle/lib/backend").unwrap();
    let device_metal = Device::new("METAL", 0);
    let is_metal_device_available = icicle_runtime::is_device_available(&device_metal);
    if is_metal_device_available {
        icicle_runtime::set_device(&device_metal).unwrap();
    } else {
        set_backend_cpu();
    }
}

pub fn init_ntt_domain(max_ntt_size: u64) {
    // Initialize NTT domain for all fields. Polynomial operations rely on NTT.
    println!(
        "Initializing NTT domain for max size 2^{}",
        max_ntt_size.trailing_zeros()
    );
    let rou_bn254: Fr = get_root_of_unity(max_ntt_size);
    initialize_domain(rou_bn254, &NTTInitDomainConfig::default()).unwrap();
}
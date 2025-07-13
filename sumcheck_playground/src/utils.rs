use icicle_core::{bignum::BigNum, traits::{Arithmetic, GenerateRandom, Invertible}};
use icicle_runtime::{runtime, Device};

pub fn set_backend_cpu() {
    let device_cpu = Device::new("CPU", 0);
    icicle_runtime::set_device(&device_cpu).unwrap();
    println!("Using CPU device");
}

pub fn try_load_and_set_backend_gpu() {
    //please put absolute path tp backend. will fix in future iterations
    runtime::load_backend("/home/administrator/users/karthik/research_POCs/cuda_backend").unwrap();
    let device_gpu = Device::new("CUDA", 0);
    let is_cuda_device_available = icicle_runtime::is_device_available(&device_gpu);
    if is_cuda_device_available {
        icicle_runtime::set_device(&device_gpu).unwrap();
        println!("Using GPU device");
    } else {
        set_backend_cpu();
        println!("Using CPU device");
    }
}
pub fn generate_random_vector<F: Arithmetic+BigNum+Invertible+GenerateRandom>(size: usize) -> Vec<F>
{
    F::generate_random(size)
}

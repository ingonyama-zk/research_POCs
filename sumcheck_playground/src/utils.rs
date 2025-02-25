use icicle_runtime::{memory::HostSlice,Device,runtime};
use icicle_core::traits::{Arithmetic,FieldImpl,GenerateRandom};

pub fn set_backend_cpu() {
    
    // icicle_runtime::load_backend("../Polynomial-API/cuda_backend/icicle/lib/backend").unwrap();
    let device_cpu = Device::new("CPU", 0);
    icicle_runtime::set_device(&device_cpu).unwrap();
}

pub fn try_load_and_set_backend_gpu() {
    
    runtime::load_backend("../cuda_backend/icicle/lib/backend").unwrap();
    let device_gpu = Device::new("CUDA", 0);
    let is_cuda_device_available = icicle_runtime::is_device_available(&device_gpu);
    if is_cuda_device_available {
        icicle_runtime::set_device(&device_gpu).unwrap();
    } else {
        set_backend_cpu();
}
}

pub fn try_load_and_set_backend_metal() {
    
    runtime::load_backend("../metal_backend").unwrap();
    let device_gpu = Device::new("METAL", 0);
    let is_cuda_device_available = icicle_runtime::is_device_available(&device_gpu);
    if is_cuda_device_available {
        icicle_runtime::set_device(&device_gpu).unwrap();
    } else {
        set_backend_cpu();
}
}
pub fn generate_random_vector<F:FieldImpl> (size:usize) -> Vec<F> 
    where 
    <F as FieldImpl>::Config: GenerateRandom<F>,
    {
    F::Config::generate_random(size)
    }

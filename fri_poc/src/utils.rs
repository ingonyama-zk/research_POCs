use bitvec::vec;
use icicle_core::
    {field::Field, hash::{HashConfig, Hasher, HasherHandle}, 
    merkle::{MerkleProof,MerkleTree,MerkleTreeConfig,PaddingPolicy}, 
    polynomials::UnivariatePolynomial, 
    traits::{Arithmetic,FieldConfig,FieldImpl,GenerateRandom}, 
    vec_ops::{add_scalars, mul_scalars, scalar_mul, slice, sub_scalars, VecOps, VecOpsConfig},
    ntt::{get_root_of_unity, initialize_domain, ntt, ntt_inplace, NTTConfig, NTTInitDomainConfig,NTTDir, NTTDomain},
    };
use icicle_runtime::{memory::HostSlice,Device};
use rand::distributions::uniform::UniformSampler;

use crate::data_structures::Friconfig;
use icicle_hash::blake2s::Blake2s;
use rayon::prelude::*;

pub fn set_backend_cpu() {
    
    // icicle_runtime::load_backend("../Polynomial-API/cuda_backend/icicle/lib/backend").unwrap();
    let device_cpu = Device::new("CPU", 0);
    icicle_runtime::set_device(&device_cpu).unwrap();
}

pub fn try_load_and_set_backend_gpu() {
    
    icicle_runtime::load_backend("../Polynomial-API/cuda_backend/icicle/lib/backend").unwrap();
    let device_gpu = Device::new("CUDA", 0);
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


pub fn generate_random_poly<P>(size: usize, from_coeffs: bool) -> P
    where
    P: UnivariatePolynomial,
    P::Field: FieldImpl,
    P::FieldConfig: GenerateRandom<P::Field>,
{
    println!("Randomizing polynomial of size {} (from_coeffs: {})", size, from_coeffs);
    let coeffs_or_evals = P::FieldConfig::generate_random(size);
    let p = if from_coeffs {
        P::from_coeffs(HostSlice::from_slice(&coeffs_or_evals), size)
    } else {
        P::from_rou_evals(HostSlice::from_slice(&coeffs_or_evals), size)
    };
    p
}

pub fn init_ntt_domain<F>(max_ntt_size: u64)
    where
        F: FieldImpl,
        <F as FieldImpl>::Config: NTTDomain<F>,
    {
        // Initialize NTT domain for all fields. Polynomial operations rely on NTT.
        println!(
            "Initializing NTT domain for max size 2^{}",
            max_ntt_size.trailing_zeros()
        );
        //test will fail when coset gen !=1
        let rou: F = get_root_of_unity::<F>(max_ntt_size);
        //test fails for coset gen!=1 since init domain doesnt accept order of primitive root !=2
        initialize_domain(rou, &NTTInitDomainConfig::default()).unwrap();
    }
pub fn num_leading_zeros(bytes: Vec<u8>) -> usize {
    let mut leading_zeros = 0;
    for byte in &bytes {
       if *byte == 0 {
           leading_zeros += 8; // A full byte of zeros
       } else {
       leading_zeros += byte.leading_zeros() as usize; // Count the zeros in the current byte
               break;
       }
   }
   leading_zeros
}

pub fn hash_fuse(a:Vec<u8>,b:Vec<u8>) -> Vec<u8>
{
    let leaf_size:u64 = 4;//for 32 bit fields
    let hasher = Blake2s::new(leaf_size).unwrap();
    let mut fused_bytes: Vec<u8> = Vec::with_capacity(a.len() + b.len());
    fused_bytes.extend_from_slice(&a);
    fused_bytes.extend_from_slice(&b);
    let cfg = HashConfig::default();
    let mut output: Vec<u8> = vec![0u8; 32];
    hasher.hash(HostSlice::from_slice(&fused_bytes), &cfg,HostSlice::from_mut_slice(&mut output)).unwrap();
    output
}

pub fn proof_of_work<F>(pow_bits:usize, transcript_challenge: F) -> u64 
where 
F:FieldImpl
{
    (0u64..u64::MAX) // Create a parallel iterator
        .find(|&nonce| {
            let mut output = hash_fuse(transcript_challenge.to_bytes_le(),  nonce.to_le_bytes().to_vec());
                 // Count leading zeros in the bit representation of the nonce
            let leading_zeros: usize = num_leading_zeros(output);
    
                // Check if the nonce meets the condition
                leading_zeros == pow_bits
            })
            .expect("No nonce found") // Safeguard: this should never trigger unless overflow

}
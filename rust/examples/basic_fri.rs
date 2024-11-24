use icicle_babybear::{
    field::{ScalarCfg, ScalarField as Fr,ExtensionField as Fr4},
    polynomials::DensePolynomial};
use icicle_core::{
    field::{self, Field}, hash::{HashConfig,Hasher}, 
    merkle::{MerkleProof, MerkleTree, MerkleTreeConfig, PaddingPolicy}, 
    ntt::{self, get_root_of_unity, initialize_domain, ntt, NTTConfig, NTTInitDomainConfig}, 
    polynomials::{UnivariatePolynomial}, traits::{FieldImpl, GenerateRandom},
};

use icicle_hash::{blake2s::Blake2s};

use icicle_runtime::{config, memory::{DeviceVec, HostOrDeviceSlice, HostSlice}};
use icicle_runtime::{self, Device};


fn init_ntt_domain(max_ntt_size: u64) {
    // Initialize NTT domain for all fields. Polynomial operations rely on NTT.
    println!(
        "Initializing NTT domain for max size 2^{}",
        max_ntt_size.trailing_zeros()
    );
    let rou_baby_bear:Fr = get_root_of_unity(max_ntt_size);
    initialize_domain(rou_baby_bear, &NTTInitDomainConfig::default()).unwrap();
}
fn main(){

icicle_runtime::load_backend("../cuda_backend").unwrap();
let _ = icicle_runtime::load_backend_from_env_or_default();
    
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
println!("Polynomial log_degree size: {:?}",10);
let logsize=14;
println!("max_domain size needed: {:?}", logsize);
icicle_runtime::set_device(&device_gpu).unwrap();
init_ntt_domain(1 << logsize);


// let layer0_poly= generate_random::<DensePolynomial>(size, false);
// layer0_poly.print();

// // let fri_layer0_tree = commit_fn::<DensePolynomial>(layer0_poly.clone());
// // let fri_layer0_root:&[u8]=fri_layer0_tree.get_root().unwrap();

// let beta = Fr::from_u32(1);
// let layer1_poly= fold_poly::<DensePolynomial>(&layer0_poly, beta);
// layer1_poly.print();
// // let fri_layer1_tree = commit_fn::<DensePolynomial>(layer1_poly.clone());
// // let fri_layer1_root:&[u8]=fri_layer1_tree.get_root().unwrap();

// let beta = Fr::from_u32(2);
// let layer2_poly= fold_poly::<DensePolynomial>(&layer1_poly, beta);
// layer2_poly.print();

// let beta = Fr::from_u32(3);
// let layer3_poly= fold_poly::<DensePolynomial>(&layer2_poly, beta);
// layer3_poly.print();

}   




pub fn generate_random<P> (
    size: usize,
    from_coeffs:bool
)-> P
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


pub fn fold_poly <P:UnivariatePolynomial>(
    poly: &DensePolynomial,
    beta: Fr,
) -> DensePolynomial {
    let o = poly.odd();
    let e = poly.even();
    &e + &(&o*&beta)
}

pub fn commit_fn <P:UnivariatePolynomial>(
    mut poly: DensePolynomial,
) -> MerkleTree
{
    let leaf_size = 4;
    
    let hasher = Blake2s::new(leaf_size).unwrap();
    let compress = Blake2s::new(hasher.output_size()*2).unwrap();
    let tree_height = poly.get_nof_coeffs().ilog2() as usize;

    let layer_hashes: Vec<&Hasher> = std::iter::once(&hasher)
        .chain(std::iter::repeat(&compress).take(tree_height))
        .collect();
    //binary tree
    let config = MerkleTreeConfig::default();
    
    let poly_slice = poly.coeffs_mut_slice();
    let merkle_tree = MerkleTree::new(&layer_hashes, leaf_size, 0).unwrap();
    
    let _ = merkle_tree
        .build(poly_slice,&config);
    
    merkle_tree
}

#[test]

pub fn test_commit_and_fold(){
    let v = vec![Fr::from_u32(1),Fr::from_u32(2),Fr::from_u32(3),Fr::from_u32(4)];
    println!("p= 1 + 2 x + 3x^2 + 4 x^3");
    println!("p = p_e(x^2) + x p_o(x^2)");
    println!("p = (1 + 3 x^2) + x (2+4x^2)");
    let p = DensePolynomial::from_coeffs(HostSlice::from_slice(&v), v.len());
    p.print();
    let tree = commit_fn::<DensePolynomial>(p.clone());
    let comm: &[u8] = tree.get_root().unwrap();
    println!("commitment: {:?}",Fr::from_bytes_le(comm));
    p.odd().print();
    p.even().print();
    let p_fold = fold_poly::<DensePolynomial>(&p, Fr::from_u32(1));
    p_fold.print();
}

#[test]

pub fn random_commit_test(){
    let size: usize = 1024;
    let logsize=14;
    println!("max_domain size needed: {:?}", logsize);
    init_ntt_domain(1 << logsize);
    let  p1= generate_random::<DensePolynomial>(size, false);
    let  tree = commit_fn::<DensePolynomial>(p1);
    let comm: &[u8] = tree.get_root().unwrap();
    println!("commitment: {:?}",Fr::from_bytes_le(comm));
    
}
use std::iter;

use icicle_babybear::{
    field::{ExtensionField as Fr4, ScalarCfg, ScalarField as Fr},
    polynomials::DensePolynomial};
use icicle_core::{
    field::Field, hash::{HashConfig,Hasher}, 
    merkle::{MerkleProof, MerkleTree, MerkleTreeConfig, PaddingPolicy}, 
    ntt::{get_root_of_unity, initialize_domain, ntt, NTTConfig, NTTInitDomainConfig}, 
    polynomials::UnivariatePolynomial, traits::{Arithmetic, FieldImpl, GenerateRandom},
    vec_ops::{add_scalars, mul_scalars, scalar_mul, slice, sub_scalars, VecOps, VecOpsConfig}
};

use icicle_hash::{blake2s::Blake2s};

use icicle_runtime::{config, memory::{DeviceSlice, DeviceVec, HostOrDeviceSlice, HostSlice}};
use icicle_runtime::{self, Device};
use rand::{random, Rng};


pub struct Friproof<F: FieldImpl> {
    pub(crate) commit_phase_commits: Vec<F>,
    pub(crate) query_index_eval: Vec<F>,
    pub(crate) query_proofs: Vec<Vec<F>>,
    pub(crate) final_poly:F,

}

struct  Frilayerdata {
    pub(crate) code_word_list: Vec<DensePolynomial>,
    pub(crate) merkle_tree: Vec<MerkleTree>,
}

struct Frilayer
{
    pub(crate) current_code_word: DensePolynomial,
}

impl Frilayer
{    
    fn fold_poly(
        &mut self,
        beta: Fr,// this should be in extension field for FRI security. currently unsupported
    ) -> DensePolynomial {
        let o = self.current_code_word.odd();
        let e = self.current_code_word.even();
        &e + &(&o*&beta)
    }

    fn commit(
        &mut self
    ) -> MerkleTree
    {
        let leaf_size = 4;//for 32 bit fields
        
        let hasher = Blake2s::new(leaf_size).unwrap();
        let compress = Blake2s::new(hasher.output_size()*2).unwrap();
        let tree_height = self.current_code_word.get_nof_coeffs().ilog2() as usize;
    
        let layer_hashes: Vec<&Hasher> = std::iter::once(&hasher)
            .chain(std::iter::repeat(&compress).take(tree_height))
            .collect();
        //binary tree
        let config = MerkleTreeConfig::default();
        
        let poly_slice = self.current_code_word.coeffs_mut_slice();
        let merkle_tree = MerkleTree::new(&layer_hashes, leaf_size, 0).unwrap();
        
        let _ = merkle_tree
            .build(poly_slice,&config);
        
        merkle_tree
    }

    fn layer_query(
        query_index: u64,
        mut layer_code_word: DensePolynomial,
        layer_merkle_tree: MerkleTree,
    ) -> MerkleProof {
            let config = MerkleTreeConfig::default();
            layer_merkle_tree.get_proof(layer_code_word.coeffs_mut_slice(), query_index, false,&config).unwrap()
    }

}

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

let poly = generate_random::<DensePolynomial>(size, false);
let mut commits: Vec<Fr>= vec![];
let mut tree_vec: Vec<MerkleTree> =vec![];
let mut evaluation_vector: Vec<DensePolynomial> = vec![];
let mut query_proof_data: Vec<Vec<Fr>> = vec![];
let mut index_poly_evals:Vec<Fr> =vec![];
let mut final_polynomial_data: Fr = Fr::zero();

let mut frilayer=Frilayer {
    current_code_word: poly,
};
let mut frilayerdata = Frilayerdata{
    code_word_list:evaluation_vector,
    merkle_tree:tree_vec,
};

let mut friproof=Friproof{
    commit_phase_commits: commits,
    query_proofs: query_proof_data,
    final_poly:final_polynomial_data,
    query_index_eval: index_poly_evals,
};

// for layers in 0..logsize-1{ 
//     //compute merkle tree and put it in a vector
//     frilayerdata.merkle_tree.push(Frilayer::commit(&mut frilayer));
//     //prover keep track of code word
//     frilayerdata.code_word_list.push(frilayer.current_code_word);
//     //compute root and put it in a vector
//     let mut comm: &[u8] = tree_vec[layers].get_root().unwrap();
//     friproof.commit_phase_commits.push(Fr::from_bytes_le(comm));

//     //simulate fiat shamir
//     let mut beta = Fr::from_u32(layers.try_into().unwrap());
    
//     //calculate fri folding
//     let final_p;
//     if frilayer.current_code_word.get_nof_coeffs() == 1 {
//         //final round is const if not error
//         final_p = frilayer.current_code_word.get_coeff(0); 
//     } else {
//         frilayer.current_code_word = Frilayer::fold_poly(&mut frilayer, beta);
//         final_p = frilayer.current_code_word.get_coeff(0);        
//     }
//     friproof.final_poly = final_p;
// }  
// //calculate index for query
// let mut rng = rand::thread_rng();
// //number of times query runs
// let query: Vec<usize> = (0..10) // Specify the number of elements you want (10 here)
//     .map(|_| rng.gen_range(0..=size-1))
//     .collect();

// for query_index in query {
//     let config = MerkleTreeConfig::default();
//         for layers in 0..logsize-1{
//             let layer_code_word = &frilayerdata.code_word_list[layers];
//             let query_leaf= layer_code_word.get_coeff(query_index.try_into().unwrap());
//             friproof.query_index_eval.push(query_leaf.clone());
//             let mut proof_query_index = frilayerdata.merkle_tree[layers].get_proof(&leaves, query_index.try_into().unwrap(), false, &config);
//         }
// }

}
// let friproof =Friproof::<Fr> {
//     commit_phase_commits: commits,
//     query_proofs: ,
//     final_poly: final_p,
// };


// let layer0_poly= generate_random::<DensePolynomial>(size, false);
// layer0_poly.print();

// // let fri_layer0_tree = commit::<DensePolynomial>(layer0_poly.clone());
// // let fri_layer0_root:&[u8]=fri_layer0_tree.get_root().unwrap();

// let beta = Fr::from_u32(1);
// let layer1_poly= fold_poly::<DensePolynomial>(&layer0_poly, beta);
// layer1_poly.print();
// // let fri_layer1_tree = commit::<DensePolynomial>(layer1_poly.clone());
// // let fri_layer1_root:&[u8]=fri_layer1_tree.get_root().unwrap();

// let beta = Fr::from_u32(2);
// let layer2_poly= fold_poly::<DensePolynomial>(&layer1_poly, beta);
// layer2_poly.print();

// let beta = Fr::from_u32(3);
// let layer3_poly= fold_poly::<DensePolynomial>(&layer2_poly, beta);
// layer3_poly.print();




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
    beta: Fr,// this should be in extension field for FRI security. currently unsupported
) -> DensePolynomial {
    let o = poly.odd();
    let e = poly.even();
    &e + &(&o*&beta)
}

pub fn check_Schwarz_Zippel <P:UnivariatePolynomial> (
    p1: &DensePolynomial,
    p2: &DensePolynomial,
) {
    let r = Fr::from_u32(random::<u32>());
    assert_eq!(p1.eval(&r),p2.eval(&r))
}

pub fn fold_vec <F:FieldImpl>(
    mut v: Vec<Fr>,
    rou: Fr,
    alpha: Fr,
) -> Vec<Fr>
{
    let rou_inv = rou.inv();    
    let len:usize = v.len();
    let lenu64:u64 = len.try_into().unwrap();
    let gen = Fr::one();
    
    let mut rou_inv_vec: Vec<Fr> = iter::successors(Some(gen), |p| Some(*p * rou_inv))
        .take(len/2)
        .collect();

    let rou_inv_slice =HostSlice::from_mut_slice(&mut rou_inv_vec[..]);
    let v_slice = HostSlice::from_mut_slice(&mut v[..]);
   //init arrays
    let mut v1 = vec![Fr::zero(); len / 2];
    let mut v2 = vec![Fr::zero(); len / 2];
    let mut odd = vec![Fr::zero(); len / 2];
    let mut even = vec![Fr::zero(); len / 2];
    let mut even1 = vec![Fr::zero(); len / 2];
    let mut even2 = vec![Fr::zero(); len / 2];
    let mut res = vec![Fr::zero(); len / 2];
    let mut resf = vec![Fr::zero(); len / 2];
    let mut odd_slice = HostSlice::from_mut_slice(&mut odd[..]);
    let mut even_slice =  HostSlice::from_mut_slice(&mut even[..]);
    let mut even1_slice =  HostSlice::from_mut_slice(&mut even1[..]);
    let mut even2_slice =  HostSlice::from_mut_slice(&mut even2[..]);
    let mut res_slice =  HostSlice::from_mut_slice(&mut res[..]);
    let mut resf_slice =  HostSlice::from_mut_slice(&mut resf[..]);
    let v1_slice = HostSlice::from_mut_slice(&mut v1[..]);
    let v2_slice = HostSlice::from_mut_slice(&mut v2[..]);
    let cfg = VecOpsConfig::default();
    //get odd and even slice
    let _ = slice(v_slice, 0, 1, lenu64, lenu64/2, &cfg, v1_slice);
    let _ = slice(v_slice, lenu64/2, 1, lenu64, lenu64/2, &cfg, v2_slice);
    //o=v1(x)+v2(-x)
    add_scalars(v1_slice, v2_slice,odd_slice, &cfg).unwrap();
    //e=v1(x)-v2(-x)
    sub_scalars(v1_slice, v2_slice, even_slice, &cfg).unwrap();
    //e1= e* w^{-i}
    mul_scalars(rou_inv_slice, even_slice, even1_slice, &cfg).unwrap();
    //e2=e* w^{-i}*alpha
    scalar_mul(HostSlice::from_slice(&mut [alpha]), even1_slice, even2_slice, &cfg).unwrap();
    //o+e2
    add_scalars(odd_slice, even2_slice, res_slice, &cfg).unwrap();
    let two_inv:Field<1, ScalarCfg> = Fr::from_u32(2).inv();
    scalar_mul(HostSlice::from_mut_slice(&mut [two_inv]), res_slice, resf_slice, &cfg).unwrap();
    let res: Vec<Fr> = resf_slice.as_slice().to_vec();
    res
}

pub fn commit <P:UnivariatePolynomial>(
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

pub fn test_commit_and_fold_coeffs(){
    let size: usize = 4;
    let logsize=2;
    let v = vec![Fr::from_u32(1),Fr::from_u32(2),Fr::from_u32(3),Fr::from_u32(4)];
    println!("p= 1 + 2 x + 3x^2 + 4 x^3");
    init_ntt_domain(1 << logsize);

    let p = DensePolynomial::from_coeffs(HostSlice::from_slice(&v), v.len());
    p.print();
    let tree = commit::<DensePolynomial>(p.clone());
    let comm: &[u8] = tree.get_root().unwrap();
    println!("commitment: {:?}",Fr::from_bytes_le(comm));
    println!("p = p_e(x^2) + x p_o(x^2)");
    println!("p_e = (1 + 3 x^2), p_o=(2+4x^2)");
    p.odd().print();
    p.even().print();
    println!("p_fold = p_e+ gamma p_o");
    let gamma = Fr::from_u32(2);
    let p_fold = fold_poly::<DensePolynomial>(&p, gamma);
    p_fold.print();
}
#[test]

pub fn test_commit_and_fold_evals(){
    let size: usize = 4;
    let logsize=2;
    println!("max_domain size needed: {:?}", logsize);
    init_ntt_domain(1 << logsize);
    
    let v = vec![Fr::from_u32(1),Fr::from_u32(2),Fr::from_u32(3),Fr::from_u32(4)];
    println!("p= 1 + 2 x + 3x^2 + 4 x^3");
    let p = DensePolynomial::from_rou_evals(HostSlice::from_slice(&v), v.len());
    p.print();
    let tree = commit::<DensePolynomial>(p.clone());
    let comm: &[u8] = tree.get_root().unwrap();
    println!("commitment: {:?}",Fr::from_bytes_le(comm));
    println!("p = p_e(x^2) + x p_o(x^2)");
    println!("p_e = (1 + 3 x^2), p_o=(2+4x^2)");
    p.odd().print();
    p.even().print();
    println!("p_fold = p_e+ gamma p_o");
    let gamma = Fr::from_u32(2);
    let p_fold = fold_poly::<DensePolynomial>(&p, gamma);
    p_fold.print();
    let mut evals = vec![Fr::zero();  size/2];
    let mut eval_slice = HostSlice::from_mut_slice(&mut evals[..]);
    p_fold.eval_on_rou_domain(logsize/2, eval_slice);
    println!("p fold evals {:?}",eval_slice); 
}

#[test]

pub fn vector_fold_test(){
    let size: usize = 4;
    let logsize=2;
    init_ntt_domain(1 << logsize);
    let v = vec![Fr::from_u32(1),Fr::from_u32(2),Fr::from_u32(3),Fr::from_u32(4)];
    let gamma = Fr::from_u32(2);
    let v_fold = fold_vec::<Fr>(v, get_root_of_unity(size.try_into().unwrap()), gamma);
    println!("fold vec {:?} ",v_fold);
}

#[test]
pub fn poly_fold_vector_fold_sanity(){
    let size: usize = 4;
    let logsize=2;
    init_ntt_domain(1 << logsize);
    let v = vec![Fr::from_u32(1),Fr::from_u32(2),Fr::from_u32(3),Fr::from_u32(4)];
    let p = DensePolynomial::from_rou_evals(HostSlice::from_slice(&v), v.len());
    let gamma = Fr::from_u32(2);
    let p_fold = fold_poly::<DensePolynomial>(&p, gamma);
    let mut evals = vec![Fr::zero();  size/2];
    let mut eval_slice = HostSlice::from_mut_slice(&mut evals[..]);
    p_fold.eval_on_rou_domain(logsize/2, eval_slice);
    println!("p fold evals {:?}",eval_slice); 
    let v_fold = fold_vec::<Fr>(v, get_root_of_unity(size.try_into().unwrap()), gamma);
    println!("fold vec in evals {:?} ",v_fold);
}

#[test]
pub fn random_poly_fold_vector_fold_sanity(){
    let size: usize = 4;
    let logsize=2;
    init_ntt_domain(1 << logsize);
    let v = vec![Fr::from_u32(1),Fr::from_u32(2),Fr::from_u32(3),Fr::from_u32(4)];
    let p = DensePolynomial::from_rou_evals(HostSlice::from_slice(&v), v.len());
    let gamma = Fr::from_u32(2);
    let p_fold = fold_poly::<DensePolynomial>(&p, gamma);
    let mut evals = vec![Fr::zero();  size/2];
    let mut eval_slice = HostSlice::from_mut_slice(&mut evals[..]);
    p_fold.eval_on_rou_domain(logsize/2, eval_slice);
    println!("p fold evals {:?}",eval_slice); 
    let v_fold = fold_vec::<Fr>(v, get_root_of_unity(size.try_into().unwrap()), gamma);
    println!("fold vec in evals {:?} ",v_fold);
}
#[test]

pub fn random_commit_and_verify_test(){
    let size: usize = 1024;
    let logsize=14;
    println!("max_domain size needed: {:?}", logsize);
    init_ntt_domain(1 << logsize);
    let  mut p1= generate_random::<DensePolynomial>(size, false);
    let mut path = vec![Fr::zero(); size];
    let config = MerkleTreeConfig::default();
    let  tree =commit::<DensePolynomial>(p1.clone());
    let comm: &[u8] = tree.get_root().unwrap();
    println!("commitment: {:?}",Fr::from_bytes_le(comm));
    let proof = tree.get_proof(p1.clone().coeffs_mut_slice(), 2, false, &config).unwrap();
    tree.verify(&proof);
}


#[test]
pub fn random_inv_test(){
    let t1 = Fr::from_u32(random::<u32>()); 
    let t1_inv = t1.inv();
    assert_eq!(t1*t1_inv,Fr::one());
}
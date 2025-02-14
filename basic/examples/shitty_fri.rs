use std::{iter, ops::Deref};
use hex;
use icicle_babybear::{
    field::{ExtensionField as Fr4, ScalarCfg, ScalarField as Fr},
    polynomials::DensePolynomial};
use icicle_core::{
    field::Field, hash::{HashConfig,Hasher}, merkle::{MerkleProof, MerkleTree, MerkleTreeConfig, PaddingPolicy}, ntt::{get_root_of_unity, initialize_domain, ntt, NTTConfig, NTTInitDomainConfig}, polynomials::UnivariatePolynomial, traits::{Arithmetic, FieldImpl, GenerateRandom}, vec_ops::{add_scalars, mul_scalars, scalar_mul, slice, sub_scalars, VecOps, VecOpsConfig}
};

use icicle_hash::{blake2s::Blake2s};

use icicle_runtime::{config, memory::{DeviceSlice, DeviceVec, HostOrDeviceSlice, HostSlice}};
use icicle_runtime::{self, Device};
use rand::{random, Rng};


pub struct Friproof<F: FieldImpl> {
    pub(crate) commit_phase_commits: Vec<F>,
    pub(crate) query_index_eval: Vec<F>,
    pub(crate) query_index_eval_sym: Vec<F>,
    pub(crate) query_proofs: Vec<MerkleProof>,
    pub(crate) query_proofs_sym: Vec<MerkleProof>,
    pub(crate) final_poly:F,

}

impl <F: FieldImpl> Friproof<F> {
    pub fn verify_path( 
        query_index_eval : F,
        query_proof: MerkleProof,
        cfg: MerkleTreeConfig,
        tree_height: usize,
     )
     where 
        F: FieldImpl,
      {
        let path = query_proof.get_path::<F>();
        let leaf = query_proof.get_leaf::<F>().0;
        let leaf = query_proof.get_leaf::<F>().1;
        let leaf_root = query_proof.get_root::<F>();
        let hasher = Blake2s::new(4).unwrap(); // Hash input in 6-byte chunks.
        let compress = Blake2s::new(hasher.output_size() * 2).unwrap(); // Compress two child nodes into one.

        let layer_hashes: Vec<&Hasher> = std::iter::once(&hasher)
            .chain(std::iter::repeat(&compress).take(tree_height))
            .collect();
        let verifier_tree = MerkleTree::new(&layer_hashes, 4, 0).unwrap();
        let proof_is_valid = verifier_tree.verify(&query_proof)
        .unwrap();
        assert!(proof_is_valid)
    }
}

struct  Frilayerdata {
    ///pub(crate) code_word_list: Vec<DensePolynomial>,
    pub(crate) code_word_list: Vec<Vec<Fr>>,
    pub(crate) merkle_tree: Vec<MerkleTree>,
}

struct Frilayer
{
    pub(crate) current_code_word: Vec<Fr>,
}

impl Frilayer
{    
    /// fold should take F in domain L, and compute
    /// F_e= (F(x)+F(-x))/2 , F_o = (F(x) - F(-x))/(2x) Poly API directly gets this result
    /// F' = F_e + beta * F_o is computed in coeff form. 
    /// F' native domain is now L^2
    // fn fold_poly(
    //     &mut self,
    //     beta: Fr,// this should be in extension field for FRI security. currently unsupported
    // ) -> DensePolynomial {
    //     let o = self.current_code_word.odd();
    //     let e = self.current_code_word.even();
    //     &e + &(&o*&beta)
    // }

    pub fn fold_vec <F:FieldImpl>(
        &mut self,
        rou: Fr,
        alpha: Fr,
    ) -> Vec<Fr>
    {
        let rou_inv = rou.inv();    
        let len:usize = self.current_code_word.len();
        let lenu64:u64 = len.try_into().unwrap();
        let gen = Fr::one();
        
        let mut rou_inv_vec: Vec<Fr> = iter::successors(Some(gen), |p| Some(*p * rou_inv))
            .take(len/2)
            .collect();
    
        let rou_inv_slice =HostSlice::from_mut_slice(&mut rou_inv_vec[..]);
        let v_slice = HostSlice::from_mut_slice(&mut self.current_code_word[..]);
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
    fn commit(
        &mut self
    ) -> MerkleTree
    {
        let leaf_size = 4;//for 32 bit fields
        
        let hasher = Blake2s::new(leaf_size).unwrap();
        let compress = Blake2s::new(hasher.output_size()*2).unwrap();
        let tree_height = self.current_code_word.len().ilog2() as usize;
    
        let layer_hashes: Vec<&Hasher> = std::iter::once(&hasher)
            .chain(std::iter::repeat(&compress).take(tree_height))
            .collect();
        //binary tree
        let config = MerkleTreeConfig::default();
        
        let poly_slice = self.current_code_word.as_mut_slice();
        let merkle_tree = MerkleTree::new(&layer_hashes, leaf_size, 0).unwrap();
        
        let _ = merkle_tree
            .build(HostSlice::from_slice(poly_slice), &config);
        
        merkle_tree
    }

    fn layer_query(
        query_index: u64,
        mut layer_code_word: Vec<Fr>,
        layer_merkle_tree: &MerkleTree,
    ) -> MerkleProof {
            let config = MerkleTreeConfig::default();
            layer_merkle_tree.get_proof(HostSlice::from_slice(&layer_code_word), query_index, false,&config).unwrap()
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

let size: usize = 16;
println!("Polynomial log_degree size: {:?}",10);
let logsize=4;
println!("max_domain size needed: {:?}", logsize);
icicle_runtime::set_device(&device_gpu).unwrap();
init_ntt_domain(1 << logsize);

let poly_eval:Vec<Fr> = <Fr as FieldImpl>::Config::generate_random(size);
let mut commits: Vec<Fr>= vec![];
let mut tree_vec: Vec<MerkleTree> =vec![];
let mut evaluation_vector: Vec<Vec<Fr>> = vec![];
let mut query_proof_data: Vec<MerkleProof> =vec![MerkleProof::new().unwrap()];
let mut query_proof_data_sym: Vec<MerkleProof> =vec![MerkleProof::new().unwrap()];
let mut query_evals:Vec<Fr> =vec![];
let mut query_evals_sym:Vec<Fr> =vec![];
let mut final_polynomial_data: Fr = Fr::zero();

let mut frilayer=Frilayer {
    current_code_word: poly_eval,
};
let mut frilayerdata = Frilayerdata{
    code_word_list:evaluation_vector,
    merkle_tree:tree_vec,
};

let mut friproof=Friproof{
    commit_phase_commits: commits,
    query_proofs: query_proof_data,
    query_proofs_sym: query_proof_data_sym,
    final_poly:final_polynomial_data,
    query_index_eval: query_evals,
    query_index_eval_sym: query_evals_sym,
};
let rou_init:Fr = get_root_of_unity(size.try_into().unwrap());

let mut acc_rou: Fr = Fr::one();

for layers in 0..logsize-1{ 
    //compute commit of current code word
    if frilayer.current_code_word.len() == 1 {
        //final round is const if not error
        //append final poly to proof
        friproof.final_poly = frilayer.current_code_word[0];
        break;
    }

    let layer_tree: MerkleTree = Frilayer::commit(&mut frilayer);
   
    //update domain for each fold
    acc_rou = acc_rou * rou_init;
    frilayerdata.code_word_list.push(frilayer.current_code_word.clone());
    // initialize_domain(acc_rou, &NTTInitDomainConfig::default()).unwrap();
   
   //append commit root to proof
    {
    let comm:&[u8] = layer_tree.get_root().unwrap();
    friproof.commit_phase_commits.push(Fr::from_bytes_le(comm));
    }
    // Prover stores tree for query phase
    frilayerdata.merkle_tree.push(layer_tree);

    //simulate fiat shamir
    let mut beta = Fr::from_u32(layers.try_into().unwrap());
    
    //folding factor 1/2 f=  f_e + beta* f_o
    //frilayer.current_code_word = Frilayer::fold_poly(&mut frilayer, beta);
    frilayer.current_code_word = Frilayer::fold_vec::<Fr>(&mut frilayer, acc_rou, beta);
}  
//calculate index for query

let mut rng = rand::thread_rng();
//number of times query runs
let query: Vec<usize> = (0..1) // Specify the number of elements you want (1 here)
    .map(|_| rng.gen_range(0..=size / 2 - 1) as usize)
    .collect();


println!("len frilayerdata.codewordslist {:?}",frilayerdata.code_word_list.len());
for query_index in query.iter()  {
        for layers in 0..=logsize-2{
            let mut layer_size = frilayerdata.code_word_list[layers].len();
            let mut index = query_index % layer_size;
            let mut index_sym = (query_index + layer_size / 2) % layer_size;
            friproof.query_index_eval.push(frilayerdata.code_word_list[layers][index]); 
            friproof.query_index_eval_sym.push(frilayerdata.code_word_list[layers][index_sym]); 
            friproof.query_proofs.push(
                Frilayer::layer_query(index.try_into().unwrap(),frilayerdata.code_word_list[layers].clone(),  &frilayerdata.merkle_tree[layers])
            );
            friproof.query_proofs_sym.push(
                Frilayer::layer_query(index_sym.try_into().unwrap(),frilayerdata.code_word_list[layers].clone(),  &frilayerdata.merkle_tree[layers])
            );
        }
}

//verifier
let roots = friproof.commit_phase_commits;
let query_index = friproof.query_index_eval;
let _query_index_sym = friproof.query_index_eval_sym;
let query_proofs = friproof.query_proofs.pop().unwrap();
let query_proofs_sym = friproof.query_proofs_sym;
let index_length = roots.len();

Friproof::verify_path(query_index[0],query_proofs, MerkleTreeConfig::default(), logsize);

// for value in query_proofs{
//     let mut path = value.get_path::<Fr>();
//     let mut leaf= value.get_leaf::<Fr>().0;
//     let mut len = path.len();
// }

// for i in 0..index_length {
//     let _ = frilayerdata.merkle_tree[i].verify(&query_proofs[i]);
//     let _ = frilayerdata.merkle_tree[i].verify(&query_proofs_sym[i]);
    
// }

}


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




// pub fn generate_random<P> (
//     size: usize,
//     from_coeffs:bool
// )-> P
// where 
//     P: UnivariatePolynomial,
//     P::Field: FieldImpl,
//     P::FieldConfig: GenerateRandom<P::Field>,
// {
// println!("Randomizing polynomial of size {} (from_coeffs: {})", size, from_coeffs);
// let coeffs_or_evals = P::FieldConfig::generate_random(size);
// let p = if from_coeffs {
//     P::from_coeffs(HostSlice::from_slice(&coeffs_or_evals), size)
// } else {
//     P::from_rou_evals(HostSlice::from_slice(&coeffs_or_evals), size)
// };
// p
// }


// pub fn fold_poly <P:UnivariatePolynomial>(
//     poly: &DensePolynomial,
//     beta: Fr,// this should be in extension field for FRI security. currently unsupported
// ) -> DensePolynomial {
//     let o = poly.odd();
//     let e = poly.even();
//     &e + &(&o*&beta)
// }

// pub fn check_Schwarz_Zippel <P:UnivariatePolynomial> (
//     p1: &DensePolynomial,
//     p2: &DensePolynomial,
// ) {
//     let r = Fr::from_u32(random::<u32>());
//     assert_eq!(p1.eval(&r),p2.eval(&r))
// }

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

// pub fn commit <P:UnivariatePolynomial>(
//     mut poly: DensePolynomial,
// ) -> MerkleTree
// {
//     let leaf_size = 4;
    
//     let hasher = Blake2s::new(leaf_size).unwrap();
//     let compress = Blake2s::new(hasher.output_size()*2).unwrap();
//     let tree_height = poly.get_nof_coeffs().ilog2() as usize;
//     println!("tree height {:?}",tree_height);
//     let layer_hashes: Vec<&Hasher> = std::iter::repeat(&compress).take(tree_height)
//         .collect();
//     //binary tree
//     let mut config = MerkleTreeConfig::default();
//     config.padding_policy= PaddingPolicy::ZeroPadding;
//     let poly_slice = poly.coeffs_mut_slice();
//     let merkle_tree = MerkleTree::new(&layer_hashes, leaf_size, 0).unwrap();
    
//     let _ = merkle_tree
//         .build(poly_slice,&config);
    
//     merkle_tree
// }

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
    p_fold.print();
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
    let logsize=10;
    println!("max_domain size needed: {:?}", logsize);
    init_ntt_domain(1 << logsize);
    let  mut p1= generate_random::<DensePolynomial>(size, false);
    
    let mut config = MerkleTreeConfig::default();
    config.padding_policy= PaddingPolicy::ZeroPadding;
    let tree =commit::<DensePolynomial>(p1.clone());
    
    let comm =tree.get_root::<Fr>().unwrap();
    println!("commitment: {:?}",comm);
    let proof = tree.get_proof(p1.clone().coeffs_mut_slice(), 2, false, &config).unwrap();
    let leaf_size = 4;//for 32 bit fields
        
    let hasher = Blake2s::new(leaf_size).unwrap();
    let compress = Blake2s::new(hasher.output_size()*2).unwrap();
    let tree_height = size.ilog2() as usize;

    let layer_hashes: Vec<&Hasher> = std::iter::repeat(&compress).take(tree_height)
        .collect();
    //binary tree
    let tree_verifier = MerkleTree::new(&layer_hashes, leaf_size, 0).unwrap();
    println!("Verifier comm {:?}",tree_verifier.get_root::<Fr>().unwrap()) ;
}


// #[test]
// pub fn random_inv_test(){
//     let t1 = Fr::from_u32(random::<u32>()); 
//     let t1_inv = t1.inv();
//     assert_eq!(t1*t1_inv,Fr::one());
// }
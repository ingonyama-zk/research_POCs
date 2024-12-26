use std::{iter, ops::Deref};
use hex;
use icicle_babybear::{
    field::{ExtensionField as Fr4, ScalarCfg, ScalarField as Fr},
    polynomials::{DensePolynomial}};
use icicle_core::{
    field::Field, hash::{HashConfig,Hasher}, merkle::{MerkleProof, MerkleTree, MerkleTreeConfig, PaddingPolicy}, ntt::{get_root_of_unity, initialize_domain, ntt, ntt_inplace, NTTConfig, NTTInitDomainConfig,NTTDir}, polynomials::UnivariatePolynomial, traits::{Arithmetic, FieldImpl, GenerateRandom}, vec_ops::{add_scalars, mul_scalars, scalar_mul, slice, sub_scalars, VecOps, VecOpsConfig}
};

use icicle_hash::{blake2s::Blake2s};

use icicle_runtime::{config, memory::{DeviceSlice, DeviceVec, HostOrDeviceSlice, HostSlice}};
use icicle_runtime::{self, Device};
use rand::{random, Rng};

fn init_ntt_domain(max_ntt_size: u64) {
    // Initialize NTT domain for all fields. Polynomial operations rely on NTT.
    println!(
        "Initializing NTT domain for max size 2^{}",
        max_ntt_size.trailing_zeros()
    );
    //test will fail when coset gen !=1
    let coset_gen: Fr =Fr::from_u32(1u32);
    let coset_rou_baby_bear: Fr = get_root_of_unity::<Fr>(max_ntt_size) * coset_gen;
    //test fails for coset gen!=1 since init domain doesnt accept order of primitive root !=2
    initialize_domain(coset_rou_baby_bear, &NTTInitDomainConfig::default()).unwrap();
}

struct Frilayer_testing
{
    pub(crate) current_code_word: Vec<Fr>,
    pub(crate) poly: DensePolynomial,
}

impl Frilayer_testing
{    
    // / fold should take F in domain L, and compute
    // / F_e= (F(x)+F(-x))/2 , F_o = (F(x) - F(-x))/(2x) Poly API directly gets this result
    // / F' = F_e + beta * F_o is computed in coeff form. 
    // / F' native domain is now L^2
fn fold_poly(
    &mut self,
    beta: Fr,// this should be in extension field for FRI security. currently unsupported
) -> DensePolynomial {
    let o: DensePolynomial = self.poly.odd();
    let e: DensePolynomial = self.poly.even();
    &e + &(&o*&beta)
}

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
}

#[test]
pub fn poly_fold_vector_fold_sanity(){
    let size: usize = 8;
    let logsize=3;
    // this cannot compute cosets
    init_ntt_domain(1 << logsize);
    let v = vec![Fr::from_u32(1),Fr::from_u32(2),Fr::from_u32(3),Fr::from_u32(4),Fr::from_u32(5),Fr::from_u32(6),Fr::from_u32(7),Fr::from_u32(8)];
    let p = DensePolynomial::from_rou_evals(HostSlice::from_slice(&v), v.len());
    let gamma = Fr::from_u32(2);
    let mut frilayer = Frilayer_testing {
        current_code_word: v.clone(),
        poly: p.clone(),
    };
    let p_fold = frilayer.fold_poly(gamma);
    let mut p_foldcopy = p_fold.clone();

    p_fold.print();
    let mut evals = vec![Fr::zero();  size/2];
    let mut eval_slice = HostSlice::from_mut_slice(&mut evals[..]);
    p_fold.eval_on_rou_domain(logsize-1, eval_slice);
    println!("p fold evals : coset gen =1 {:?}",eval_slice); 


    let mut conf: NTTConfig<_> =NTTConfig::<Fr>::default();
    conf.coset_gen= Fr::from_u32(3u32);
    let mut eval_slicecopy = p_foldcopy.coeffs_mut_slice();
    ntt_inplace(eval_slicecopy,NTTDir::kForward, &conf);
    let mut evalscopy = vec![Fr::zero();  size/2];
    let mut eval_slice2 = HostSlice::from_mut_slice(&mut evalscopy[..]);
    eval_slicecopy.copy_to_host(eval_slice2).unwrap();
    println!("p fold evals : coset gen =3 {:?}",eval_slice2); 


    //vec ops is a low level api can compute any coset folding (dumb stupid way)
    let coset_gen: Fr = Fr::from_u32(1u32);
    let coset_rou_baby_bear: Fr = get_root_of_unity::<Fr>(size.try_into().unwrap()) * coset_gen;
    let v_fold = frilayer.fold_vec::<Fr>(coset_rou_baby_bear, gamma);
    println!("fold vec in evals: coset gen =1  {:?} ",v_fold);

    let coset_gen: Fr = Fr::from_u32(3u32);
    let coset_rou_baby_bear: Fr = get_root_of_unity::<Fr>(size.try_into().unwrap()) * coset_gen;
    let v_fold = frilayer.fold_vec::<Fr>(coset_rou_baby_bear, gamma);
    println!("fold vec in evals: coset gen =3  {:?} ",v_fold);
}

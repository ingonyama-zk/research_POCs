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
    let rou_baby_bear: Fr = get_root_of_unity::<Fr>(max_ntt_size);
    //test fails for coset gen!=1 since init domain doesnt accept order of primitive root !=2
    initialize_domain(rou_baby_bear, &NTTInitDomainConfig::default()).unwrap();
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
    coset_gen: Fr,
    alpha: Fr,
) -> Vec<Fr>
{
    let rou_inv = rou.inv();    
    let len:usize = self.current_code_word.len();
    let lenu64:u64 = len.try_into().unwrap();
    let gen = Fr::one();
    
    //(1,w^{-1},w^{-2},...)
    let mut rou_inv_vec: Vec<Fr> = iter::successors(Some(gen), |p| Some(*p * rou_inv))
        .take(len/2)
        .collect();

    let mut rou_inv_slicebc =HostSlice::from_mut_slice(&mut rou_inv_vec[..]);
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
    let mut rouf=  vec![Fr::zero(); len / 2];  
    let mut odd_slice = HostSlice::from_mut_slice(&mut odd[..]);
    let mut even_slice =  HostSlice::from_mut_slice(&mut even[..]);
    let mut even1_slice =  HostSlice::from_mut_slice(&mut even1[..]);
    let mut even2_slice =  HostSlice::from_mut_slice(&mut even2[..]);
    let mut res_slice =  HostSlice::from_mut_slice(&mut res[..]);
    let mut resf_slice =  HostSlice::from_mut_slice(&mut resf[..]);
    let v1_slice = HostSlice::from_mut_slice(&mut v1[..]);
    let v2_slice = HostSlice::from_mut_slice(&mut v2[..]);

    let mut rou_inv_slice = HostSlice::from_mut_slice(&mut rouf[..]);
    let cfg = VecOpsConfig::default();
    // g^{-1}(1,w^{-1},w^{-2},...)
    scalar_mul(HostSlice::from_slice(&mut [coset_gen.inv()]), rou_inv_slicebc, rou_inv_slice, &cfg).unwrap();
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

pub fn poly_fold_vector_fold_sanity_no_coset(){
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
    let mut evals = vec![Fr::zero();  size/2];
    let mut eval_slice = HostSlice::from_mut_slice(&mut evals[..]);
    let p_fold = frilayer.fold_poly(gamma);
    p_fold.eval_on_rou_domain(logsize-1, eval_slice);
    println!("p fold evals : coset gen =1 {:?}",eval_slice); 

    let rou_baby_bear: Fr = get_root_of_unity::<Fr>(size.try_into().unwrap());
    let v_fold = frilayer.fold_vec::<Fr>(rou_baby_bear, Fr::from_u32(1u32),gamma);
    println!("fold vec in evals: coset gen =1  {:?} ",v_fold);
}

/// original domain H: [1,w,w^2,...]
/// folded original domain H^2: [1,w^2,w^4,...]
/// coset:D: g[1,w,w^2,...]
/// Folded coset: D^2: g^2[1,w^2,w^4,...]
/// v = [a_0,a_1,a_2,a_3,a_4,a_5,a_6,a_7]
/// Coset_Ntt_D[v] = v_eval in D
/// v_{fold} = (v[gw^i] + v[-gw^i])/2 +  beta(v[gw^i] - v[-gw^i])/2gw^i |_{i=0..n/2} evals in D^2
/// P(X) coeff form with a_i as coefficients in H
/// P_fold(x) = P.even + \beta p.odd in H^2
/// P_{fold}(g^2 x) = NTT_D^2(P_{fold}(x))

#[test]
pub fn poly_fold_vector_fold_sanity_coset(){

    let size: usize = 8;
    let logsize=3;
    // this cannot compute cosets
    init_ntt_domain(1 << logsize);
    //v in native
    let v = vec![Fr::from_u32(1),Fr::from_u32(2),Fr::from_u32(3),Fr::from_u32(4),Fr::from_u32(5),Fr::from_u32(6),Fr::from_u32(7),Fr::from_u32(8)];
    //p in coeff form
    let p = DensePolynomial::from_coeffs(HostSlice::from_slice(&v.clone()), v.len());

    //init coset and get v into coset eval form
    let mut cfg = NTTConfig::<Fr>::default();
    cfg.coset_gen = Fr::from_u32(3u32);
    let mut v_evals = vec![Fr::zero();  size];
    let v_slice = HostSlice::from_slice(&v);
    let v_eval_coset = HostSlice::from_mut_slice(&mut v_evals[..]);
    ntt(v_slice, NTTDir::kForward, &cfg, v_eval_coset).unwrap();
    let v_eval_coset_vec:Vec<Fr>=v_eval_coset.as_slice().to_vec();


    let gamma = Fr::from_u32(2);
    let mut frilayer = Frilayer_testing {
        current_code_word: v_eval_coset_vec.clone(),
        poly: p.clone(),
    };
    //fold coset eval vec.
    let coset_gen3: Fr = Fr::from_u32(3u32);
    let rou_baby_bear: Fr = get_root_of_unity::<Fr>(size.try_into().unwrap());
    let v_fold = frilayer.fold_vec::<Fr>(rou_baby_bear, coset_gen3,gamma);
    println!("fold vec in evals: coset D^2  {:?} ",v_fold);

    //fold poly in coeff
    let p_fold = frilayer.fold_poly(gamma);
    let mut coset_sq_evals = vec![Fr::zero();  size/2];
    let mut coset_sq_eval_slice = HostSlice::from_mut_slice(&mut coset_sq_evals[..]);
    //when there is different coset g(1,w,w^2..), the folded poly is in coset
    // g^2(1,w^2,w^4,...)
    let coset_gen_sq =coset_gen3*coset_gen3;   
    let rou_sq = rou_baby_bear*rou_baby_bear;
    let coset_domain_sq:Vec<Fr> = iter::successors(Some(Fr::one()), |p| Some(*p * rou_sq))
    .take((size as u64 / 2).try_into().unwrap())
    .map(|x| x*coset_gen_sq)
    .collect();


    p_fold.eval_on_domain(HostSlice::from_slice(&coset_domain_sq), coset_sq_eval_slice);
    println!("p fold evals : coset gen D^2 {:?}",coset_sq_eval_slice.as_slice().to_vec());

}



use std::iter;


use icicle_core::
    {merkle::MerkleTree, 
    polynomials::UnivariatePolynomial, 
    traits::{Arithmetic,FieldImpl},
    ntt::{get_root_of_unity,ntt,NTTConfig,NTTDir},
    };

use icicle_runtime::memory::HostSlice;



use icicle_babybear::{
    field::ScalarField as Fr,
    polynomials::DensePolynomial};

use fri_poc::data_structures::*;
use fri_poc::utils::*;
use rand::Rng;




fn fold_poly(
    poly: DensePolynomial,
    beta: Fr,// this should be in extension field for FRI security. currently unsupported
) -> DensePolynomial {
    let o: DensePolynomial = poly.odd();
    let e: DensePolynomial = poly.even();
    &e + &(&o*&beta)
}

fn fold_poly2<P: UnivariatePolynomial>(
    poly: P,      
    beta: P::Field, 
) -> P {
    let o = poly.odd();  // Get the odd terms
    let e = poly.even(); // Get the even terms
    // Perform the fold operation: e + (o * beta)
    let o_beta = o.mul_by_scalar(&beta);  // o * beta (polynomial * scalar)
    e.add(&o_beta)  // e + (o * beta) (addition of polynomials)
}
#[test]
pub fn foldpoly1vs2test(){
    let size: usize = 8;
    let logsize=3;
    // this cannot compute cosets
    init_ntt_domain::<Fr>(1 << logsize);
    let v = vec![Fr::from_u32(1),Fr::from_u32(2),Fr::from_u32(3),Fr::from_u32(4),Fr::from_u32(5),Fr::from_u32(6),Fr::from_u32(7),Fr::from_u32(8)];
    let poly = DensePolynomial::from_rou_evals(HostSlice::from_slice(&v), v.len());
    let gamma = Fr::from_u32(200);
    let p_fold = fold_poly(poly.clone(), gamma);
    let p_fold2 = fold_poly2(poly, gamma);
    let  mut t1 = vec![Fr::zero();  size/2];
    let  mut t2 = vec![Fr::zero();  size/2];
    p_fold.copy_coeffs(0, HostSlice::from_mut_slice(t1.as_mut_slice()));
    p_fold2.copy_coeffs(0, HostSlice::from_mut_slice(t2.as_mut_slice()));
    println!("p fold evals1 {:?}",t1);
    println!("p fold evals2 {:?}",t2);
}
#[test]

pub fn poly_fold_vector_fold_sanity_no_coset(){
    let size: usize = 8;
    let logsize=3;
    // this cannot compute cosets
    init_ntt_domain::<Fr>(1 << logsize);
    let v = vec![Fr::from_u32(1),Fr::from_u32(2),Fr::from_u32(3),Fr::from_u32(4),Fr::from_u32(5),Fr::from_u32(6),Fr::from_u32(7),Fr::from_u32(8)];
    let poly = DensePolynomial::from_rou_evals(HostSlice::from_slice(&v), v.len());
    let gamma = Fr::from_u32(200);
    let mut frilayer =  Current_layer::<Fr> {
        current_code_word: v.clone(),
    };

    let mut evals = vec![Fr::zero();  size/2];
    let eval_slice = HostSlice::from_mut_slice(&mut evals[..]);
    let p_fold = fold_poly(poly, gamma);
    p_fold.eval_on_rou_domain(logsize-1, eval_slice);
    println!("p fold evals : coset gen =1 {:?}",eval_slice); 

    let v_fold = frilayer.fold_evals( Fr::from_u32(1u32),gamma);
    println!("fold vec in evals: coset gen =1  {:?} ",v_fold);

    let rou = get_root_of_unity::<Fr>(size.try_into().unwrap());
    let rou_inv= rou.inv();
    let two_inv = (Fr::from_u32(2)).inv();
    let mut f_e = Vec::<Fr>::new();
    let mut f_o = Vec::<Fr>::new();
    let mut f_f = Vec::<Fr>::new();
    for i in 0..size/2{
        f_e.push((v[i]+v[i+4])*two_inv);
        f_o.push((v[i]-v[i+4])*two_inv* pow(rou_inv, i.try_into().unwrap()));
        f_f.push(f_e[i] + gamma * f_o[i]);
    }
    println!("manual compute {:?}" , f_f);
}

// original domain H: [1,w,w^2,...]
// folded original domain H^2: [1,w^2,w^4,...]
// coset:D: g[1,w,w^2,...]
// Folded coset: D^2: g^2[1,w^2,w^4,...]
// v = [a_0,a_1,a_2,a_3,a_4,a_5,a_6,a_7]
// Coset_Ntt_D[v] = v_eval in D
// v_{fold} = (v[gw^i] + v[-gw^i])/2 +  beta(v[gw^i] - v[-gw^i])/2gw^i |_{i=0..n/2} evals in D^2
// P(X) coeff form with a_i as coefficients in H
// P_fold(x) = P.even + \beta p.odd in H^2
// P_{fold}(g^2 x) = NTT_D^2(P_{fold}(x))
#[test]
pub fn poly_fold_vector_fold_sanity_coset(){

    let size: usize = 8;
    let logsize=3;
    // this cannot compute cosets
    init_ntt_domain::<Fr>(1 << logsize);
    //v in native
    let v = vec![Fr::from_u32(1),Fr::from_u32(2),Fr::from_u32(3),Fr::from_u32(4),Fr::from_u32(5),Fr::from_u32(6),Fr::from_u32(7),Fr::from_u32(8)];
    //p in coeff form
    let poly = DensePolynomial::from_coeffs(HostSlice::from_slice(&v.clone()), v.len());

    //init coset and get v into coset eval form
    let mut cfg = NTTConfig::<Fr>::default();
    cfg.coset_gen = Fr::from_u32(3u32);
    let mut v_evals = vec![Fr::zero();  size];
    let v_slice = HostSlice::from_slice(&v);
    let v_eval_coset = HostSlice::from_mut_slice(&mut v_evals[..]);
    ntt(v_slice, NTTDir::kForward, &cfg, v_eval_coset).unwrap();
    let v_eval_coset_vec:Vec<Fr>=v_eval_coset.as_slice().to_vec();


    let gamma = Fr::from_u32(2);
    let mut frilayer = Current_layer::<Fr> {
        current_code_word: v_eval_coset_vec.clone(),
    };
    //fold coset eval vec.
    let coset_gen3: Fr = Fr::from_u32(3u32);
    let rou_baby_bear: Fr = get_root_of_unity::<Fr>(size.try_into().unwrap());
    let v_fold = frilayer.fold_evals( coset_gen3,gamma);
    println!("fold vec in evals: coset D^2  {:?} ",v_fold);

    //fold poly in coeff
    let p_fold = fold_poly(poly,gamma);
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
#[test]
pub fn poly_extend_poly(){

    let size: usize = 8;
    let logsize=3;
    let new_domainsize = size*2;
    let new_logsize=new_domainsize.ilog2();
    // this cannot compute cosets
    init_ntt_domain::<Fr>(1 << new_logsize);
    //v in native
    let mut v:Vec<Fr> = vec![Fr::from_u32(1),Fr::from_u32(2),Fr::from_u32(3),Fr::from_u32(4),Fr::from_u32(5),Fr::from_u32(6),Fr::from_u32(7),Fr::from_u32(8)];
    let mut vz:Vec<Fr> = vec![Fr::zero(),Fr::zero(),Fr::zero(),Fr::zero(),Fr::zero(),Fr::zero(),Fr::zero(),Fr::zero()];    
    //p in coeff form
    v.append(&mut vz);
    let mut poly = DensePolynomial::from_coeffs(HostSlice::from_slice(&v.clone()), new_domainsize);
    poly.print();
    let mut new_domain_evals = vec![Fr::zero();  new_domainsize];
    let mut new_domain_eval_size = HostSlice::from_mut_slice(&mut new_domain_evals[..]);
    let mut cfg = NTTConfig::<Fr>::default();
    ntt(poly.coeffs_mut_slice(), NTTDir::kForward, &cfg, new_domain_eval_size).unwrap();
    println!("P on big domain {:?} ",new_domain_eval_size.as_slice().to_vec());
    let v_b =coeff_to_eval_blowup::<Fr>(v, size*2);
    println!("Vec on big domain  {:?}",v_b);
}

#[test]
pub fn fold_evals_test(){
    try_load_and_set_backend_gpu();
    let size: usize = 8;
    let logsize=3;
    // this cannot compute cosets
    init_ntt_domain::<Fr>(1 << logsize);
    //v in native
    let v = vec![Fr::from_u32(1),Fr::from_u32(2),Fr::from_u32(3),Fr::from_u32(4),Fr::from_u32(5),Fr::from_u32(6),Fr::from_u32(7),Fr::from_u32(8)];

    //init coset and get v into coset eval form
    let mut cfg = NTTConfig::<Fr>::default();
    let rou_baby_bear: Fr = get_root_of_unity::<Fr>(size.try_into().unwrap());
    cfg.coset_gen = Fr::from_u32(3u32);
    let mut v_evals = vec![Fr::zero();  size];
    let v_slice = HostSlice::from_slice(&v);
    let v_eval_coset = HostSlice::from_mut_slice(&mut v_evals[..]);
    ntt(v_slice, NTTDir::kForward, &cfg, v_eval_coset).unwrap();
    let v_eval_coset_vec:Vec<Fr>=v_eval_coset.as_slice().to_vec();

    let mut current = Current_layer {
        current_code_word: v_eval_coset_vec.clone(),
    };
    let gamma = Fr::from_u32(2);
    let v_fold =current.fold_evals(cfg.coset_gen,gamma);
    println!("fold vec in evals: coset D^2  {:?} ",v_fold);
}

#[test]

pub fn commit_and_verify(){
    let v = vec![Fr::from_u32(1),Fr::from_u32(2),Fr::from_u32(3),Fr::from_u32(4),Fr::from_u32(5),Fr::from_u32(6),Fr::from_u32(7),Fr::from_u32(8)];
//    let v:Vec<Fr> = <Fr as FieldImpl>::Config::generate_random(size)
    let mut current = Current_layer {
        current_code_word: v.clone(),
    };
    let tree: MerkleTree = current.commit();
    let proof = current.layer_query(1, &tree);
    let result = current.test_verify_path(proof);
    println!("result {:?}",result);
    assert!(result);
    drop(tree);
}

#[test]
pub fn commit_and_verify_random(){
    try_load_and_set_backend_gpu();
    let size:usize = 131072;
    let test_vec = generate_random_vector::<Fr>(size);
    let mut current = Current_layer {
        current_code_word: test_vec.clone(),
    };
    let mut rng = rand::thread_rng();
    let r:u64 = rng.gen_range(0..size).try_into().unwrap();
    let tree: MerkleTree = current.commit();
    let proof = current.layer_query(r, &tree);
    let result = current.test_verify_path(proof);
    assert!(result);
    drop(tree);
}

use icicle_core::traits::FieldImpl;
use log::debug;
use merlin::Transcript;
use icicle_babybear::field::ScalarField as Fr;

use fri_poc::{data_structures::*, verifier::verify};
use fri_poc::utils::*;
use fri_poc::transcript::*;
use fri_poc::prover::*;


#[test]

fn diagnostic_prover_test() {
    let fri_config: Friconfig = Friconfig {
        blow_up_factor: 4,
        folding_factor: 2,
        pow_bits: 10,
        num_queries: 1,
        stopping_size: 1,//2^0
    };

let starting_size: usize = 8;

//let mut input_data: Vec<Fr> = generate_random_vector::<Fr>(starting_size);
let input_data: Vec<Fr> = vec![Fr::from_u32(1),Fr::from_u32(2),Fr::from_u32(3),Fr::from_u32(4),Fr::from_u32(5),Fr::from_u32(6),Fr::from_u32(7),Fr::from_u32(8)];
debug!("input_data {:?}",input_data);
let size: usize = input_data.len()*fri_config.blow_up_factor;
debug!("size*blowup {:?}",size);
debug!("stopping size{:?}",fri_config.stopping_size);

let is_coeff=true;//coeffs of a poly
let mut code_word: Vec<Fr> = if is_coeff {
    //degree =2^k-1, i,e size = 2^k
    //if input is in coeff form and codeword required is 2^k*blowup
    coeff_to_eval_blowup::<Fr>(input_data.clone(), size)
} else { 
    //eval = 2^k and we need size = 2^k*blowup
    eval_to_eval_blowup::<Fr>(input_data.clone(), size)
};
//println!("code_word {:?}",code_word);
let num_rounds = size.ilog2()-fri_config.stopping_size.ilog2();
let mut prover_transcript = Transcript::new(b"Shitty_FRI");

let friproof:Friproof<Fr>  = prove::<Fr>(
    fri_config,
    &mut prover_transcript,
    code_word.clone());
debug!("final_poly {:?}",friproof.final_poly);

let nr:usize =num_rounds.try_into().unwrap();
for q in 0..fri_config.num_queries{
    let mut it= 0;
    for query_proof in friproof.query_proofs.iter().skip(q*nr).take(nr) {
    it+=1;
    debug!("query number {:?}, layer number {:?}, leaf_layer {:?}, leaf_ayersym {:?}",q,it, query_proof[0].get_leaf::<Fr>(),query_proof[1].get_leaf::<Fr>());
    }
}

let mut verifier_transcript = Transcript::new(b"Shitty_FRI");

verify(fri_config, friproof, &mut verifier_transcript).unwrap();
}

//cargo test --package fri_poc --test e2etests -- e2e_fri_test --exact --show-output
#[test]
fn e2e_fri_test(){

    let fri_config: Friconfig = Friconfig {
        blow_up_factor: 4,
        folding_factor: 2,
        pow_bits: 10,
        num_queries: 50,
        stopping_size: 256,//2^0
    };

let starting_size: usize = 1<<16;
let input_data: Vec<Fr> = generate_random_vector::<Fr>(starting_size);
let size: usize = input_data.len()*fri_config.blow_up_factor;


let is_coeff=true;//coeffs of a poly
let code_word: Vec<Fr> = if is_coeff {
    //degree =2^k-1, i,e size = 2^k
    //if input is in coeff form and codeword required is 2^k*blowup
    coeff_to_eval_blowup::<Fr>(input_data.clone(), size)
} else { 
    //eval = 2^k and we need size = 2^k*blowup
    eval_to_eval_blowup::<Fr>(input_data.clone(), size)
};

let mut prover_transcript = Transcript::new(b"Real_FRI");

let friproof:Friproof<Fr>  = prove::<Fr>(
    fri_config,
    &mut prover_transcript,
    code_word.clone());

let mut verifier_transcript = Transcript::new(b"Real_FRI");
verify(fri_config, friproof, &mut verifier_transcript).unwrap();
}
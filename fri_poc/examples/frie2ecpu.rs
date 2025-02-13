
use log::info;
use merlin::Transcript;
use icicle_babybear::field::ScalarField as Fr;

use fri_poc::{data_structures::*, verifier::verify};
use fri_poc::utils::*;
use fri_poc::prover::*;
use std::time::Instant;

//RUST_LOG=info cargo run --release --package fri_poc --example frie2ecpu
fn main(){
    set_backend_cpu();
    env_logger::init();
    let start = Instant::now();
    let fri_config: Friconfig = Friconfig {
        blow_up_factor: 4,
        folding_factor: 2,
        pow_bits: 10,
        num_queries: 50,
        stopping_size: 256,//2^0
    };
info!("Fri config: {:?}",fri_config);
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
info!("Code word log size: {:?}",code_word.len().ilog2());
info!("Setup: {:?}",start.elapsed());
let mut prover_transcript = Transcript::new(b"Real_FRI");
let provertime = Instant::now();
let friproof:Friproof<Fr>  = prove::<Fr>(
    fri_config,
    &mut prover_transcript,
    code_word.clone());
info!("Prove: {:?}",provertime.elapsed());
let verifiertime = Instant::now();
let mut verifier_transcript = Transcript::new(b"Real_FRI");
verify(fri_config, friproof, &mut verifier_transcript).unwrap();
info!("Verify time {:?}",verifiertime.elapsed());
info!("Total time: {:?}",start.elapsed());
}

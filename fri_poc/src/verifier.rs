use icicle_core::{
    hash::Hasher,
    merkle::{MerkleProof, MerkleTree},
    ntt::{get_root_of_unity, NTTDomain, NTT},
    traits::{Arithmetic, FieldImpl},
    vec_ops::*,
};

use crate::utils::*;
use crate::{data_structures::*, transcript::*};
use icicle_hash::blake2s::Blake2s;
use log::debug;
use merlin::Transcript;

//methods for verifier
impl<F: FieldImpl> Friproof<F> {
    //checks the path of the query proof
    pub fn verify_path(
        &mut self,
        layer_index: usize,
        leaf_index: usize,
        tree_height: usize,
    ) -> bool {
        //to replace this with generics and merkle config
        let leaf_size: u64 = (F::one()).to_bytes_le().len().try_into().unwrap(); //4 for 32 bit fields
        let hasher = Blake2s::new(leaf_size).unwrap();
        //binary tree
        let compress = Blake2s::new(hasher.output_size() * 2).unwrap();
        let layer_hashes: Vec<&Hasher> = std::iter::once(&hasher)
            .chain(std::iter::repeat(&compress).take(tree_height))
            .collect();
        let verifier_tree = MerkleTree::new(&layer_hashes, leaf_size, 0).unwrap();
        let result = verifier_tree.verify(&self.query_proofs[layer_index][leaf_index]);
        debug!("result of tree verification {:?}", result);
        match verifier_tree.verify(&self.query_proofs[layer_index][leaf_index]) {
            Ok(true) => true, // Verification succeeded
            Ok(false) => {
                eprintln!(
                    "Verification failed: Fake path detected at layer {:?} and leaf {:?}",
                    layer_index, leaf_index
                );
                false
            }
            Err(err) => {
                eprintln!(
                    "Error during verification at layer {:?} and leaf {:?}: {:?}",
                    layer_index, leaf_index, err
                );
                false
            }
        }
    }
}

pub fn verify<F>(
    fri_config: Friconfig,
    mut friproof: Friproof<F>,
    transcript: &mut Transcript,
) -> Result<bool, &'static str>
where
    F: FieldImpl + Arithmetic,
    F::Config: VecOps<F> + NTTDomain<F> + NTT<F, F>,
{
    debug!("query_proof_len {:?}", friproof.query_proofs.len());
    let exp: usize = friproof.query_proofs.len() / fri_config.num_queries;
    let exp_stop: usize = fri_config.stopping_size.ilog2().try_into().unwrap();
    let size: usize = 1 << (exp + exp_stop);
    let num_rounds = size.ilog2() - fri_config.stopping_size.ilog2();

    debug!("verifier_size {:?}", size);

    <Transcript as TranscriptProtocol<F>>::fri_domain_sep(
        transcript,
        b"my_Shitty_FRI",
        size.try_into().unwrap(),
        b"public".to_vec(),
    );

    //merkle verifyL Proof structure is as follows for folding in 2
    //[[[proof_0,proof_0sym],[proof_1,proof_1sym],...num_rounds times],....., num_queries times]

    let mut rq: usize = 0;
    let nr: usize = num_rounds.try_into().unwrap();
    for q in 0..fri_config.num_queries {
        let mut start_size = size;
        for r in 0..nr {
            let tree_height: usize = start_size.ilog2() as usize;
            debug!("query no {:?}, tree height verifier {:?}", q, tree_height);
            for j in 0..fri_config.folding_factor {
                friproof.verify_path(r + rq, j, tree_height);
            }
            //this should work for any folding factor
            start_size /= fri_config.folding_factor;
        }
        rq += nr;
    }

    let query_proofs: Vec<Vec<MerkleProof>> = friproof.query_proofs;
    //read roots from proof and gen challenge
    // we need only one root per layer, our query proofs is structured with many query proofs per query
    //

    let mut challenge_vec: Vec<F> = Vec::<F>::new();

    for query_proof in query_proofs.iter().take(num_rounds.try_into().unwrap()) {
        let current_root = query_proof[0].get_root::<F>()[0];
        <Transcript as TranscriptProtocol<F>>::append_root(transcript, b"commit", &current_root);
        challenge_vec.push(<Transcript as TranscriptProtocol<F>>::challenge_scalar(
            transcript,
            b"challenge",
        ));
    }

    debug!("challenge_vec {:?}", challenge_vec);

    //nonce check
    let current_challenge: F =
        <Transcript as TranscriptProtocol<F>>::challenge_scalar(transcript, b"challenge");
    debug!("POW_challenge {:?}", current_challenge);
    let nonce: u64 = friproof.pow_nonce;
    debug!("nonce {:?}", nonce);
    let out: Vec<u8> = hash_fuse(
        current_challenge.to_bytes_le(),
        nonce.to_le_bytes().to_vec(),
    );
    let out_lead_zeros: usize = num_leading_zeros(out);
    assert_eq!(
        out_lead_zeros, fri_config.pow_bits,
        "Nonce does not satisfy POW condition"
    );

    //add nonce to transcript
    <Transcript as TranscriptProtocol<F>>::add_nonce(transcript, nonce);

    let seed = <Transcript as TranscriptProtocol<F>>::challenge_scalar(transcript, b"sample")
        .to_bytes_le();
    debug!("Verifier_seed for sampling based on transcript {:?}", seed);
    let query_indices: Vec<usize> = generate_samples_in_range(
        seed,
        fri_config.num_queries,
        size / fri_config.folding_factor,
    );
    debug!("top layer query_indices {:?}", query_indices);

    let mut leafs: Vec<F> = Vec::<F>::new();
    let mut leafs_sym: Vec<F> = Vec::<F>::new();
    let mut indices: Vec<usize> = Vec::<usize>::new();
    let mut indices_sym: Vec<usize> = Vec::<usize>::new();
    let mut top_indices: Vec<usize> = Vec::<usize>::new();

    //here we need to collect for each query proofs, the relevant leafs and indices

    let mut rq: usize = 0;
    let nr: usize = num_rounds.try_into().unwrap();
    for _ in 0..fri_config.num_queries {
        for r in 0..nr {
            let (leaf, index) = query_proofs[r + rq][0].get_leaf::<F>();
            leafs.push(leaf[0]);
            indices.push(index.try_into().unwrap());
            let (leaf_sym, index_sym) = query_proofs[r + rq][1].get_leaf::<F>();
            leafs_sym.push(leaf_sym[0]);
            indices_sym.push(index_sym.try_into().unwrap());
        }
        rq += nr;
    }
    //top layer index:
    let mut rq: usize = 0;
    for _ in 0..fri_config.num_queries {
        top_indices.push(indices[rq]);
        rq += nr;
    }
    //index_check sanity
    for (i, j) in query_indices.iter().zip(top_indices) {
        assert_eq!(*i, j);
    }

    //collinearity check
    let mut rq: usize = 0;
    let two_inv: F = F::from_u32(2).inv();
    let nr: usize = num_rounds.try_into().unwrap();
    debug!("leafs {:?}", leafs);
    debug!("leafs sym {:?}", leafs_sym);
    for q in 0..fri_config.num_queries {
        let leafs_q = leafs[rq..rq + nr].to_vec();
        let leafs_sym_q = leafs_sym[rq..rq + nr].to_vec();
        let index_q = indices[rq..rq + nr].to_vec();
        let index_symq = indices_sym[rq..rq + nr].to_vec();
        for r in 0..nr {
            let rou = get_root_of_unity::<F>((size / (1 << r)).try_into().unwrap());
            let rou_inv = rou.inv();
            let l_even = (leafs_q[r] + leafs_sym_q[r]) * two_inv;
            let l_odd = (leafs_q[r] - leafs_sym_q[r])
                * two_inv
                * (pow(rou_inv, index_q[r].try_into().unwrap()));
            let l_next = l_even + challenge_vec[r] * l_odd;
            debug!("queryno:{:?}, round: {:?},Index: {:?}, leaf: {:?}, Index_sym: {:?}  ,leaf_sym: {:?}, computed_next_leaf: {:?}",q,r,index_q[r],leafs_q[r],index_symq[r], leafs_sym_q[r],l_next);
            if r == nr - 1 {
                assert_eq!(
                    l_next,
                    friproof.final_poly[index_q[r] % fri_config.stopping_size],
                    "collinearity test failed at final poly"
                );
            } else {
                assert_eq!(
                    l_next,
                    leafs_q[r + 1],
                    "Collinearity test failed at round {:?}",
                    r
                );
            }
        }
        rq += nr;
    }

    Ok(true)
}

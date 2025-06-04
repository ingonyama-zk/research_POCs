
use std::collections::HashMap;

use icicle_hash::sha3::Sha3_256;
use icicle_runtime::memory::HostSlice;
use icicle_core::hash::HashConfig;
use num_bigint::BigUint;
use rand::{rng, Rng};

fn main() {
    let modulus = BigUint::from(1u64) << 32;
    let mut map = HashMap::new();
    let mut rng = rng();
    let hasher = Sha3_256::new(0).unwrap();

    loop {
        // Generate a random 8-byte input
        let input: Vec<u8> = (0..8).map(|_| rng.random()).collect();
        let mut output = vec![0u8; 32];
        hasher.hash(
            HostSlice::from_slice(&input),
            &HashConfig::default(),
            HostSlice::from_mut_slice(&mut output),
        ).unwrap();

        // Interpret the hash as a big integer, then mod 2^32
        let hash_mod2pow32: BigUint = BigUint::from_bytes_be(&output) % &modulus;
        let hash_mod_u32 = hash_mod2pow32.to_u32_digits()[0];

        if let Some(prev_input) = map.insert(hash_mod_u32, input.clone()) {
            println!("Collision found!");
            println!("Input 1: {:?}", prev_input);
            println!("Input 2: {:?}", input);
            println!("Hash mod 2^32: {}", hash_mod_u32);
            break;
        }
    }
}
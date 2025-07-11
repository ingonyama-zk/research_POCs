use icicle_bn254::curve::ScalarField as Fr;
use icicle_core::{bignum::BigNum, traits::{Arithmetic, GenerateRandom}};
use rayon::prelude::*;
use std::time::Instant;

pub fn generate_random_vector<T>(size: usize) -> Vec<T>
where T: GenerateRandom+ BigNum
{
    T::generate_random(size)
}

fn serialize_vector<T>(fields: &[T]) -> Vec<u8> 
where  T: BigNum+Arithmetic
{
    let field_size = std::mem::size_of::<T>();
    let mut buffer = Vec::with_capacity(fields.len() * field_size);

    let chunks: Vec<Vec<u8>> = fields
        .par_iter()
        .map(|f| f.to_bytes_le().to_vec()) // Parallel conversion
        .collect();

    for chunk in chunks {
        buffer.extend_from_slice(&chunk);
    }

    buffer
}

fn deserialize_vector<T>(bytes: &[u8]) -> Vec<T>
where  T: BigNum+Arithmetic {
    let field_size = std::mem::size_of::<T>();
    assert!(bytes.len() % field_size == 0, "Invalid byte length");

    bytes
        .par_chunks_exact(field_size)
        .map(|chunk| {
            let array = chunk.to_vec();
            T::from_bytes_le(&array)
        })
        .collect()
}

pub fn main() {
    let size = 1 << 20;
    let start1 = Instant::now();
    println!("Generating random vector of size {}", size);
    let f = generate_random_vector::<Fr>(size);
    println!(
        "Time taken to generate random vector: {:?}",
        start1.elapsed()
    );
    let start2 = Instant::now();
    let serialized = serialize_vector(&f);
    println!("Time taken to serialize {:?}", start2.elapsed());
    let start2 = Instant::now();
    let deserialized = deserialize_vector::<Fr>(&serialized);
    println!("Time taken to deserialize {:?}", start2.elapsed());
    assert_eq!(f, deserialized);
}

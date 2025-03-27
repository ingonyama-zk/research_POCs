use icicle_bn254::curve::ScalarField as Fr;
use icicle_core::traits::{FieldImpl, GenerateRandom};
use rayon::prelude::*;
use std::time::Instant;
pub fn generate_random_vector<F: FieldImpl>(size: usize) -> Vec<F>
where
    <F as FieldImpl>::Config: GenerateRandom<F>,
{
    F::Config::generate_random(size)
}

fn serialize_vector<F: FieldImpl>(fields: &[F]) -> Vec<u8> {
    let field_size = std::mem::size_of::<F>();
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

fn deserialize_vector<F: FieldImpl>(bytes: &[u8]) -> Vec<F> {
    let field_size = std::mem::size_of::<F>();
    assert!(bytes.len() % field_size == 0, "Invalid byte length");

    bytes
        .par_chunks_exact(field_size)
        .map(|chunk| F::from_bytes_le(chunk))
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

use icicle_hash::keccak::Keccak256;
use icicle_runtime::memory::HostSlice;
use icicle_core::hash::HashConfig;

use hex;
fn main() {
    
    let input = b"Cryptographic hash functions have many information-security applications, 
    notably in digital signatures, message authentication codes (MACs), and other forms of authentication.
    They can also be used as ordinary hash functions, to index data in hash tables, 
    for fingerprinting, to detect duplicate data or uniquely identify files, 
    and as checksums to detect accidental data corruption. Indeed, 
    in information-security contexts, cryptographic hash values are sometimes called (digital) fingerprints
    , checksums, (message) digests,or just hash values, even though all these terms stand for more 
    general functions with rather different properties and purposes. Non-cryptographic hash functions 
    are used in hash tables and to detect accidental errors; their constructions frequently provide
    no resistance to a deliberate attack. For example, a denial-of-service attack on hash tables is 
    possible if the collisions are easy to find, as in the case of linear cyclic redundancy check (CRC) 
    functions";
    let mut output = vec![0u8; 32]; 
    
    let hasher = Keccak256::new(0).unwrap();
    let _ = hasher.hash(HostSlice::from_slice(input), &HashConfig::default(), HostSlice::from_mut_slice(&mut output));
    println!("inout len {:?}",input.len());
    println!("output len {:?}",output.len());
    println!("Hash: {:?}",hex::encode(output));
}
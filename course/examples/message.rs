use icicle_hash::keccak::Keccak256;
use icicle_runtime::memory::HostSlice;
use icicle_core::hash::HashConfig;

use hex;
fn main() {
    //avalanche effect
    let input1 = b"protocol1";
    let input2 = b"protocol1 ";
    let mut output1 = vec![0u8; 32]; 
    let mut output2 = vec![0u8; 32]; 
    let hasher1 = Keccak256::new(0).unwrap();
    let hasher2 = Keccak256::new(0).unwrap();
    let _ = hasher1.hash(HostSlice::from_slice(input1), &HashConfig::default(), HostSlice::from_mut_slice(&mut output1));
    let _ = hasher1.hash(HostSlice::from_slice(input2), &HashConfig::default(), HostSlice::from_mut_slice(&mut output2));
    println!("Hash: {:?}",hex::encode(output1));
    println!("Hash: {:?}",hex::encode(output2));
}
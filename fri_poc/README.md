# FRI POC

In this repository, we present a FRI POC. The repository is complete with Fiat Shamir based on Merlin, pending extension field element generation which will be fixed soon.

The algorithm of FRI is entirely built using low level API such as vector operations, field operations, and high level API such as hashes, merkle tree API, Polynomial API in the Icicle library. The same code can be run in CPU or GPU. 

The following tests can be run from the tests folder
* End to end diagnostic FRI test for a small vector
```rust
RUST_LOG=DEBUG cargo test --package fri_poc --test e2etests -- diagnostic_prover_test --exact --show-output
```
* End to end real FRI test (if u have GPU load the backend)
```rust
cargo test --release --package fri_poc --test e2etests -- e2e_fri_test --exact --show-output 
```
* Benches for a single fold iteration: Comparing folding without precompute, with precompute inverse domain and folding using polynomial API with criterion. 
```rust
cargo bench
```
* test fold poly contains a battery of tests for different features, tests are self explanatory. 
* test merlin encoding contains, some encoding tests for merlin library and a POW test based on ICICLE blake2s.
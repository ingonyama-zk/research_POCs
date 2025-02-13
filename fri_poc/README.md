# FRI POC

In this repository, we present a FRI POC. The repository is complete with Fiat Shamir based on Merlin, pending extension field element generation which will be fixed soon.

The algorithm of FRI is entirely built using low level API such as vector operations, field operations, and high level API such as hashes, merkle tree API, Polynomial API in the Icicle library. The same code can be run in CPU or GPU. 

The following tests can be run from the tests folder, two run a full example 
```rust
RUST_LOG=info cargo run --release --package fri_poc --example frie2e
```
Current performance in M1
```
[2025-02-13T14:58:43Z INFO  frie2e] Fri config: Friconfig { blow_up_factor: 4, folding_factor: 2, pow_bits: 10, num_queries: 50, stopping_size: 256 }
Initializing NTT domain for max size 2^18
[2025-02-13T14:58:43Z INFO  frie2e] Code word log size: 18
[2025-02-13T14:58:43Z INFO  frie2e] Setup: 33.732125ms
[2025-02-13T14:58:43Z INFO  frie2e] Prove: 68.743083ms
[2025-02-13T14:58:43Z INFO  frie2e] Verify time 4.82375ms
[2025-02-13T14:58:43Z INFO  frie2e] Total time: 107.332958ms
```
* End to end diagnostic FRI test for a small vector
```rust
RUST_LOG=DEBUG cargo test --package fri_poc --test e2etests -- diagnostic_prover_test --exact --show-output
```
* End to end real FRI test (if u have GPU load the backend)
```rust
cargo test --package fri_poc --test e2etests -- e2e_fri_test --exact --show-output
```
* Benches for a single fold iteration: Comparing folding without precompute, with precompute inverse domain and folding using polynomial API with criterion. 
```rust
cargo bench
```
* test fold poly contains a battery of tests for different features, tests are self explanatory. 
* test merlin encoding contains, some encoding tests for merlin library and a POW test based on ICICLE blake2s.
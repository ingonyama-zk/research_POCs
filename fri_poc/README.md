# FRI POC

In this repository, we present a FRI POC. The repository is complete with Fiat Shamir based on Merlin, pending extension field element generation which will be fixed soon.

The algorithm of FRI is entirely built using low level API such as vector operations, field operations, and high level API such as hashes, merkle tree API, Polynomial API in the Icicle library. The same code can be run in CPU or GPU. 

The following tests can be run from the tests folder, two run a full example 
```rust
RUST_LOG=info cargo run --release --package fri_poc --example frie2ecpu
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
A bit slower on a CPU

```
[2025-02-13T16:00:12Z INFO  frie2ecpu] Fri config: Friconfig { blow_up_factor: 4, folding_factor: 2, pow_bits: 10, num_queries: 50, stopping_size: 256 }
Initializing NTT domain for max size 2^18
[2025-02-13T16:00:12Z INFO  frie2ecpu] Code word log size: 18
[2025-02-13T16:00:12Z INFO  frie2ecpu] Setup: 25.631366ms
[2025-02-13T16:00:12Z INFO  fri_poc::prover] prove: Precompute domain inverse 777.736µs
[2025-02-13T16:00:12Z INFO  fri_poc::prover] prove: Commit phase 385.457123ms
[2025-02-13T16:00:12Z INFO  fri_poc::prover] prove: pow_phase 2.603882ms
[2025-02-13T16:00:12Z INFO  fri_poc::prover] prove: query phase 17.591331ms
[2025-02-13T16:00:12Z INFO  frie2ecpu] Prove: 407.479447ms
[2025-02-13T16:00:12Z INFO  frie2ecpu] Verify time 7.582593ms
[2025-02-13T16:00:12Z INFO  frie2ecpu] Total time: 440.711437ms
```
For GPU there is segmentation fault beyond `2^{12}` (this is probably due to terrible code writing), but note that it is THE SAME CODE" proving device agnosticity even while using external FS library such as merlin. The commit part currently runs in GPU, proof of work is not parallelized yet, so it is a bit wasteful to run it in GPU. Query part is constant time, so it doesn't impact much.
```
Defaulting to Ingonyama icicle-cuda-license-server at `5053@license.icicle.ingonyama.com`. For more information about icicle-cuda-license, please contact support@ingonyama.com.
[2025-02-13T15:53:44Z INFO  frie2egpu] Fri config: Friconfig { blow_up_factor: 4, folding_factor: 2, pow_bits: 10, num_queries: 50, stopping_size: 1 }
Initializing NTT domain for max size 2^12
[2025-02-13T15:53:44Z INFO  frie2egpu] Code word log size: 12
[2025-02-13T15:53:44Z INFO  frie2egpu] Setup: 8.320574ms
[2025-02-13T15:53:44Z INFO  fri_poc::prover] prove: Precompute domain inverse 15.893µs
[2025-02-13T15:53:44Z INFO  fri_poc::prover] prove: Commit phase 4.620169ms
[2025-02-13T15:53:44Z INFO  fri_poc::prover] prove: pow_phase 156.496µs
[2025-02-13T15:53:44Z INFO  fri_poc::prover] prove: query phase 1.316191ms
[2025-02-13T15:53:44Z INFO  frie2egpu] Prove: 6.14324ms
[2025-02-13T15:53:44Z INFO  frie2egpu] Verify time 1.953075ms
[2025-02-13T15:53:44Z INFO  frie2egpu] Total time: 16.421984ms
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
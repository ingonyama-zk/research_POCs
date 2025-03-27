# Sumcheck benches

`Sample size = 1<<22` FShash: Blake3, field: BN254
run `RUST_LOG=info cargo run --release --package sumcheck_playground --example prover_runtime`
Count only "Prover time" as relevant parameter.
* M1

```rust 
[2025-03-15T21:19:23Z INFO  prover_runtime] Generate e,A,B,C of log size 22, time 736.827167ms
[2025-03-15T21:19:23Z INFO  prover_runtime] Compute claimed sum time 441.050375ms
[2025-03-15T21:19:24Z INFO  prover_runtime] Prover time 475.654958ms
[2025-03-15T21:19:24Z INFO  prover_runtime] verify time 686µs
[2025-03-15T21:19:24Z INFO  prover_runtime] total time 1.654625917s
```

* CPU (Sweden)
```rust
[2025-03-15T21:41:54Z INFO  prover_runtime] Generate e,A,B,C of log size 22, time 860.305768ms
[2025-03-15T21:41:55Z INFO  prover_runtime] Compute claimed sum time 395.299247ms
[2025-03-15T21:41:55Z INFO  prover_runtime] Prover time 243.818264ms
[2025-03-15T21:41:55Z INFO  prover_runtime] verify time 1.604716ms
[2025-03-15T21:41:55Z INFO  prover_runtime] total time 1.501773809s
```

* GPU prover time:
```rust
[WARNING] Defaulting to Ingonyama icicle-cuda-license-server at `5053@license.icicle.ingonyama.com`. For more information about icicle-cuda-license, please contact support@ingonyama.com.
[2025-03-15T21:44:04Z INFO  prover_runtime] Generate e,A,B,C of log size 22, time 843.453171ms
[2025-03-15T21:44:04Z INFO  prover_runtime] Compute claimed sum time 388.208321ms
[2025-03-15T21:44:04Z INFO  prover_runtime] Prover time 214.828669ms
[2025-03-15T21:44:04Z INFO  prover_runtime] verify time 585.864µs
[2025-03-15T21:44:04Z INFO  prover_runtime] total time 1.447238835s
```
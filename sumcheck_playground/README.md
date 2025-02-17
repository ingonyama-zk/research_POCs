# Sumcheck benches

`Sample size = 1<<22` FShash: Blake3, field: BN254
run `RUST_LOG=info cargo run --release --package sumcheck_playground --example prover_runtime`
Count only "Prover time" as relevant parameter.
* M1

```rust 
[2025-02-16T21:42:03Z INFO  prover_runtime] Generate e,A,B,C of log size 22, time 825.228125ms
[2025-02-16T21:42:04Z INFO  prover_runtime] Compute claimed sum time 442.782209ms
[2025-02-16T21:42:06Z INFO  prover_runtime] Prover time 2.367392958s
[2025-02-16T21:42:06Z INFO  prover_runtime] total time 3.635556541s
```

* CPU (Sweden) No appreciable difference
```rust
[2025-02-16T21:48:02Z INFO  prover_runtime] Generate e,A,B,C of log size 22, time 893.846402ms
[2025-02-16T21:48:02Z INFO  prover_runtime] Compute claimed sum time 371.656176ms
[2025-02-16T21:48:04Z INFO  prover_runtime] Prover time 2.213439492s
[2025-02-16T21:48:04Z INFO  prover_runtime] total time 3.478999758s
```

* GPU prover time: 10X faster!
```rust
[WARNING] Defaulting to Ingonyama icicle-cuda-license-server at `5053@license.icicle.ingonyama.com`. For more information about icicle-cuda-license, please contact support@ingonyama.com.
[2025-02-16T21:45:16Z INFO  prover_runtime] Generate e,A,B,C of log size 22, time 887.082087ms
[2025-02-16T21:45:17Z INFO  prover_runtime] Compute claimed sum time 371.899565ms
[2025-02-16T21:45:17Z INFO  prover_runtime] Prover time 211.657645ms
[2025-02-16T21:45:17Z INFO  prover_runtime] total time 1.470787919s
```
# Polynomial-API

## C++ API

TOFIX, still in V2

* compile the ICICLE library for a given curve/field 
``` 
git clone https://github.com/ingonyama-zk/icicle.git --branch main -- single-branch
mkdir -p build
cmake -OPTIONS=ON/OFF -DCURVE=<CURVE> -S . -B build;
cmake --build build -j
``` 

Where <CURVE> takes one of the identifiers bn254/bls12_377/bls12_381/bw6_761/grumpkin. For available compilation options refer to [ICICLE documentation](https://dev.ingonyama.com/icicle/core) 
* ICICLE is a statically compiled library: Link the generated static libraries to your executable in Cmake by providing the appropriate path (assuming that the root directory of the application containts the cmake file). 

``` 
add_executable(
    <executable_name>
    src/file_1.cu
    src/file_2.cu
)

target_link_libraries(<executable_name> 
${CMAKE_SOURCE_DIR}/../icicle/icicle/build/lib/libingo_curve_bn254.a
${CMAKE_SOURCE_DIR}/../icicle/icicle/build/lib/libingo_field_bn254.a
${CMAKE_SOURCE_DIR}/../icicle/icicle/build/lib/libgmock_main.a
${CMAKE_SOURCE_DIR}/../icicle/icicle/build/lib/libgmock.a
${CMAKE_SOURCE_DIR}/../icicle/icicle/build/lib/libgtest_main.a
${CMAKE_SOURCE_DIR}/../icicle/icicle/build/lib/libgtest.a
)

target_include_directories(<executable_name> PRIVATE 
"/../icicle/icicle/include"
"${CMAKE_SOURCE_DIR}/include")
``` 

## RUST

In V3

* run examples

```
cargo run --package rust --example hello_poly 

```
* run test

```

cargo test --package rust --test test_integration --  --show-output
```
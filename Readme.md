# Introduction
This lib is for benchmarking multisignature scheme *only* for reaching the upper time bound.
Duplicate/unnecessary operations and messages are added to keep the code as simple as possible, which should be stripped out in the real use.

For example, we used the MtAwc instead of MtA in the Phase 2 and bind to the point of generator (underlying library breaks if used identity instead), which use more time than real scheme and reach the upper time bound.

# Known Issues
The underlying library [curv](https://github.com/ZenGo-X/curv) and [class group](https://github.com/ZenGo-X/class) both have issues in handling corresponding operations.
The first library is used for curves and big integers and the second library is used for the HSM group operations.

1. curve: breaks in secp256k1 identity point is used.
2. curve: breaks in scalar turns to 0.
3. class: terrible memory management and breaks in too many operations (i.e. too many parties in our scheme).
4. class: depends on deprecated library and must rely on the corresponding Cargo.toml.

# Modification to the class library
We modified the class library and expose the private fields in the HSM group.


# Run test
Test the multisignature library with 

`
    cargo test -p multisig -- --test-threads=1
`

For the reason shown above, the underlying library would sometimes break for large party number.
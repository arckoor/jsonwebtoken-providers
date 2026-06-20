# jsonwebtoken-providers

Some `CryptoProvider`s for [jsonwebtoken](https://github.com/Keats/jsonwebtoken).

## Development

Tests must be run with [cargo-nextest](https://nexte.st/), to ensure that the test processes remain separated.
Running with `cargo test` will fail, this is expected.
To run the tests, some data needs to be generated:

```sh
cd provider-tests
cargo run -- -k
cargo run -- -p aws-lc-rs
cargo run -- -p rust-crypto
cargo run -- -p openssl
cargo run -- -p botan
```

This generates JWTs signed with each provider, which are used to verify their signatures can be interpreted by every other provider.
See the [flake.nix](/flake.nix) for convenience wrappers.

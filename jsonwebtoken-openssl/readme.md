# jsonwebtoken-openssl

A `CryptoProvider` for [jsonwebtoken](https://github.com/Keats/jsonwebtoken), backed by [OpenSSL](https://github.com/openssl/openssl) (via the [rust-openssl](https://github.com/rust-openssl/rust-openssl) crate).

Use `jsonwebtoken_openssl::install_default()` to install the provider.

Use the following table to select the correct version:
| `jsonwebtoken` version | provider version |
|:----:|:---:|
| 10.x | 1.x |
| 11.x | 2.x |

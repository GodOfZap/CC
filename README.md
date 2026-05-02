# LFDT Challenge Submission

This project is a Rust library crate for the coding challenge.

It contains:

- Encryption function based on the scheme in the pdf
- Matching decryption function
- Tests for roundtrip encryption/decryption
- Tests for all provided vectors

Main implementation is in src/lib.rs.

Main checks used:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

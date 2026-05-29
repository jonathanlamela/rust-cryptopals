# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
cargo build          # build the project
cargo test           # run all tests
cargo test <name>    # run a single test by name (e.g. cargo test challenge_1)
cargo test set1      # run all tests in a module
```

## Architecture

This is a library crate (`src/lib.rs`) implementing solutions to the [Cryptopals crypto challenges](https://cryptopals.com/). The challenges are organized by set in test modules (`set1`, `set2`, `set3`), all gated with `#[cfg(test)]`.

**Core modules:**

- `cryptovec` — the main workhorse: a trait `CryptoVec` implemented on `Vec<u8>` that adds XOR operations, frequency analysis, AES-ECB/CBC encrypt/decrypt, padding, and attack helpers. Most challenge logic lives here.
- `hex` / `base64` — encoding/decoding wrappers used throughout the challenges.
- `crypters` — stateful AES encrypters used by oracle challenges (sets 2–3). Each `custom_crypter_NN.rs` corresponds to the oracle needed by challenge NN.
- `oracle` — the `Oracle` trait and `OracleBase` struct that wrap a key, optional prefix/suffix, IV, and mode (ECB/CBC) to simulate black-box encryption oracles.
- `usizecrypt` — helpers for working with numeric/usize-level crypto primitives.
- `errors` — `JlmCryptoErrors` enum covering the error surface.

**Challenge sets as tests:**

Each `set*.rs` file is a test module with one `#[test]` per challenge. Tests read fixture files from the `data/` directory (e.g. `data/data_6.txt`). The sets build progressively — set2 relies on set1 primitives, set3 on set2 oracles.

**Dependencies of note:**

- `openssl` crate is used for AES-CBC via `openssl::symm`.
- `rust-crypto` (forked, pinned to a branch) is used for AES-ECB via `aessafe`.
- `rand` for random key/IV generation in oracle challenges.

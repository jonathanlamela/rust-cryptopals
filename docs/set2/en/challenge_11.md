---
layout: default
title: "Challenge 11 — An ECB/CBC detection oracle"
parent: "Set 2 — EN"
nav_order: 3
permalink: /set2/en/challenge_11/
lang: en
---

# Challenge 11 — An ECB/CBC detection oracle

[← Previous](../challenge_10/) · [Next →](../challenge_12/) · [🇮🇹 Italiano](../../it/challenge_11/) · [Set 2 index](../../)

---

## Theory

A cryptographic "oracle" is a system that performs cryptographic operations on attacker-supplied input, without revealing the key. In this challenge, the oracle prepends and appends random bytes to the plaintext, then encrypts it with a random key using ECB or CBC — chosen randomly. The task is to determine which mode was used.

The detection technique exploits ECB's weakness once again: if a sufficiently long and repetitive input is provided (such as 48 all-zero bytes), at least two adjacent plaintext blocks (after prefix addition) are almost certainly identical. In ECB, identical plaintext blocks produce identical ciphertext blocks. In CBC, the chaining effect makes ciphertext blocks different even for identical plaintext blocks.

The 48-zero-byte input guarantees that, regardless of the prefix length (5–10 bytes), there are at least 32 consecutive zero bytes in the plaintext after the prefix — that is, at least two identical 16-byte blocks. If two consecutive identical blocks are found in the ciphertext, the mode is ECB.

This demonstrates a fundamental principle of security by design: the real system reveals neither the key nor the mode, but an attacker can deduce critical information simply by observing how the ciphertext changes in response to controlled inputs.

## Key concepts

- **Cryptographic oracle:** system that encrypts attacker-supplied input without revealing the key.
- **`CustomCrypter11`:** oracle with random mode (ECB/CBC) and random key.
- **ECB detection via repetitive input:** identical block input → identical ciphertext blocks in ECB.
- **`is_ecb_calculated`:** compares blocks 1 and 2 (0-indexed) of the ciphertext.
- **`USizeCrypt::random_block`:** generates a random byte vector of length `usize`.
- **Random prefix/suffix:** make detection more realistic (plaintext does not start at block boundary).

## Code walkthrough

### Overview

`src/crypters/custom_crypter_11.rs` defines `CustomCrypter11`, which uses `OracleBase` (`src/oracle/base.rs`) for encryption. The test in `src/set2.rs` creates the oracle, sends a known input, and verifies mode detection.

### Implementation

`CustomCrypter11::new`:

```rust
pub fn new() -> Result<Self, JlmCryptoErrors> {
    let mut random_generator = thread_rng();
    let mut cipher: Cipher = Cipher::aes_128_ecb();
    let mode: MODE = if random_generator.gen() {
        MODE::ECB
    } else {
        cipher = Cipher::aes_128_cbc();
        MODE::CBC
    };
    let key = cipher.block_size().random_block();
    let prefix: Vec<u8> = random_generator.gen_range(5..=10).random_block();
    let suffix: Vec<u8> = random_generator.gen_range(5..=10).random_block();
    let iv: Option<Vec<u8>> = if mode == MODE::CBC {
        Some(cipher.block_size().random_block())
    } else { None };
    Ok(CustomCrypter11 { base: OracleBase { key, prefix: Some(prefix), suffix: Some(suffix), mode, iv } })
}
```

`thread_rng().gen()` produces a random boolean to choose the mode. `random_block()` from the `USizeCrypt` trait generates random bytes.

`is_ecb_calculated` detects ECB:

```rust
pub fn is_ecb_calculated(&self, vec: Vec<u8>) -> Result<bool, JlmCryptoErrors> {
    let blocks: Vec<&[u8]> = vec.chunks(16).skip(1).take(2).collect();
    Ok(blocks[0] == blocks[1])
}
```

It skips the first block (which might be partially affected by the prefix) and compares the second and third. If they are equal, the mode is ECB.

`OracleBase::encrypt` handles the actual encryption by concatenating prefix + input + suffix, then encrypting in CBC or ECB.

### The test

```rust
#[test]
pub fn challenge_11() {
    let oracle = CustomCrypter11::new();
    match oracle {
        Ok(r) => {
            let input: Vec<u8> = vec![0; 48];
            let encrypted_value = r.base.encrypt(&input).unwrap();
            if r.is_cbc() {
                assert_eq!(r.is_ecb_calculated(encrypted_value).unwrap(), false);
            } else if r.is_ecb() {
                assert_eq!(r.is_ecb_calculated(encrypted_value).unwrap(), true);
            }
        }
        Err(_) => { panic!(); }
    }
}
```

The 48-zero-byte input guarantees repeated blocks in the plaintext. The test verifies that `is_ecb_calculated` agrees with the oracle's actual mode.

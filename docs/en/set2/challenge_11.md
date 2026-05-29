---
layout: default
title: "Challenge 11 — ECB/CBC detection oracle"
parent: "Set 2 EN"
grand_parent: EN
nav_order: 3
permalink: /en/set2/challenge_11/
lang: en
---

# Challenge 11 — ECB/CBC detection oracle

[← Previous](../challenge_10/) · [Next →](../challenge_12/) · [🇮🇹 Italiano](../../../it/set2/challenge_11/) · [Set 2](../) · [Home](../../)

---

## Theory

A cryptographic oracle is a system that performs cryptographic operations and returns the result to an attacker while keeping the key secret. In this challenge, the oracle randomly chooses whether to encrypt in ECB or CBC mode, adds a random prefix and suffix to the plaintext, and returns the ciphertext. The task is to determine which mode was used by observing only the ciphertext.

The detection principle is the same as challenge 8: ECB produces identical blocks for identical plaintext blocks. If we supply a sufficiently long and repetitive input (for example, 48 zero bytes), the repeated bytes will occupy at least two consecutive blocks in the plaintext after the prefix is added (which can be up to 10 bytes). With ECB, these two identical plaintext blocks will produce identical ciphertext blocks; with CBC, they will not (thanks to chaining).

The use of repetitive inputs is a fundamental technique in oracle cryptanalysis. In subsequent sets, this technique is refined to extract information byte by byte about secret data (challenges 12 and 14).

The random oracle in challenge 11 uses `CustomCrypter11`, which randomly chooses ECB or CBC, generates a random key and IV, and adds a random prefix and suffix (5–10 bytes) to the plaintext.

## Key concepts

- **Encryption oracle**: system that encrypts attacker-provided inputs revealing the ciphertext but not the key.
- **ECB detection via repeated blocks**: technique exploiting ECB's deterministic property to detect its use.
- **`CustomCrypter11`**: struct simulating an oracle with randomly chosen ECB or CBC mode.
- **`OracleBase`**: struct holding key, IV, prefix, suffix, and mode, with a generic `encrypt` method.
- **`is_ecb_calculated`**: method checking whether two consecutive ciphertext blocks are identical.
- **Repetitive plaintext**: 48 identical-byte input used to guarantee repeated blocks after prefix addition.

## Code walkthrough

### Overview

The challenge uses `src/crypters/custom_crypter_11.rs` for the oracle and `src/oracle/base.rs` for shared encryption logic. The `Oracle` trait in `src/oracle/mod.rs` defines the contract.

### Implementation

`CustomCrypter11::new()` builds the oracle with random parameters:

```rust
pub fn new() -> Result<Self, JlmCryptoErrors> {
    let mut random_generator = thread_rng();
    let mut cipher: Cipher = Cipher::aes_128_ecb();
    let mode: MODE = if random_generator.gen() { MODE::ECB } else {
        cipher = Cipher::aes_128_cbc(); MODE::CBC
    };
    let key = cipher.block_size().random_block();
    let prefix: Vec<u8> = random_generator.gen_range(5..=10).random_block();
    let suffix: Vec<u8> = random_generator.gen_range(5..=10).random_block();
    let iv: Option<Vec<u8>> = if mode == MODE::CBC { Some(cipher.block_size().random_block()) } else { None };
    Ok(CustomCrypter11 { base: OracleBase { key, prefix: Some(prefix), suffix: Some(suffix), mode, iv } })
}
```

`is_ecb_calculated` checks whether two ciphertext blocks are identical:

```rust
pub fn is_ecb_calculated(&self, vec: Vec<u8>) -> Result<bool, JlmCryptoErrors> {
    let blocks: Vec<&[u8]> = vec.chunks(16).skip(1).take(2).collect();
    Ok(blocks[0] == blocks[1])
}
```

Skips the first block (which contains the prefix) and compares the second and third blocks. With 48 zero bytes of input and a prefix of at most 10 bytes, blocks 1 and 2 (0-indexed) always contain identical bytes in ECB mode.

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
        Err(_) => panic!(),
    }
}
```

The test verifies that ECB/CBC detection is consistent with the mode actually used by the oracle.

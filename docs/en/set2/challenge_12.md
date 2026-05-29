---
layout: default
title: "Challenge 12 — Byte-at-a-time ECB decryption (simple)"
parent: "Set 2 EN"
grand_parent: EN
nav_order: 4
permalink: /en/set2/challenge_12/
lang: en
---

# Challenge 12 — Byte-at-a-time ECB decryption (simple)

[← Previous](../challenge_11/) · [Next →](../challenge_13/) · [🇮🇹 Italiano](../../../it/set2/challenge_12/) · [Set 2](../) · [Home](../../)

---

## Theory

The "byte-at-a-time" attack is one of the most elegant attacks against ECB oracles. The oracle encrypts in ECB `controlled_prefix || secret_suffix`. The attacker can choose the prefix but does not know the suffix. The goal is to recover the secret suffix byte by byte.

The principle is as follows: if we supply `n-1` bytes of input (where `n` is the block size), the oracle will encrypt the block `[our (n-1) bytes || first byte of suffix]`. We can precompute the ciphertext of all 256 possible blocks `[our (n-1) bytes || X]` for each value X from 0 to 255, and compare with the real result to find the value of the first suffix byte. Once the first byte is known, we can use `n-2` bytes of our input to expose the second byte, and so on.

This technique is applicable to any system that: uses ECB, encrypts `attacker_controlled || secret` with the same key every time, and returns the ciphertext. Many session cookies and web tokens of the 2000s were vulnerable to this attack.

The "simple" version (challenge 12) has no oracle-controlled prefix. The "harder" version (challenge 14) adds a random prefix that must first be neutralized.

## Key concepts

- **Byte-at-a-time decryption**: technique recovering a secret suffix one byte at a time by manipulating block alignment.
- **`get_suffix`**: `CustomCrypter12` method implementing the full attack to recover the suffix.
- **`prefix_plus_suffix_length`**: method calculating the total length of prefix + suffix from padding behavior.
- **`prefix_length`**: method calculating the oracle prefix length.
- **Block alignment**: manipulation of input length to position the target byte at the start of a new block.
- **`chunks_count`**: `USizeCrypt` trait method calculating how many complete blocks N bytes occupy and how many fill bytes are needed.

## Code walkthrough

### Overview

The challenge uses `src/crypters/custom_crypter_12.rs` for the oracle and `src/usizecrypt/mod.rs` for alignment utilities.

### Implementation

`get_suffix` recovers the secret suffix byte by byte:

```rust
pub fn get_suffix(&self) -> Result<Vec<u8>, JlmCryptoErrors> {
    let prefix_len = self.prefix_length().unwrap();
    let suffix_len = self.prefix_plus_suffix_length().unwrap() - prefix_len;
    let (prefix_chunks_count, prefix_fill_len) = prefix_len.chunks_count();
    let mut suffix = Vec::new();
    let mut input = vec![0; prefix_fill_len + Self::BLOCK_SIZE - 1];
    let virtual_ciphertexts = (0..Self::BLOCK_SIZE)
        .map(|left_shift| self.base.encrypt(&input[left_shift..]))
        .collect::<Result<Vec<Vec<u8>>, JlmCryptoErrors>>()
        .unwrap();
    for i in 0..suffix_len {
        let block_index = prefix_chunks_count + i / Self::BLOCK_SIZE;
        let left_shift = i % Self::BLOCK_SIZE;
        for u in 0u8..=255 {
            input.push(u);
            if virtual_ciphertexts[left_shift][block_index * Self::BLOCK_SIZE..(block_index + 1) * Self::BLOCK_SIZE]
                == self.base.encrypt(&input[left_shift..]).unwrap()[block_index * Self::BLOCK_SIZE..(block_index + 1) * Self::BLOCK_SIZE]
            {
                suffix.push(u);
                break;
            }
            input.pop();
        }
    }
    Ok(suffix)
}
```

For each suffix byte `i`, computes the block it falls in (`block_index`) and the shift (`left_shift`). Compares the corresponding block of the virtual ciphertext (precomputed) with the block of the ciphertext obtained by appending candidate byte `u`. When they match, the byte is found.

### The test

```rust
#[test]
pub fn challenge_12() {
    let oracle = CustomCrypter12::new();
    let base64_suffix = Base64::from_string(String::from("Um9sbGluJyBpbiBteSA1LjAK..."));
    match oracle {
        Ok(r) => {
            let input: Vec<u8> = b"A".to_vec();
            let encrypted_value = r.base.encrypt(&input).unwrap();
            assert_eq!(encrypted_value.len() % 16, 0);
            assert_eq!(base64_suffix, Base64::from_bytes(r.get_suffix().unwrap().as_slice()))
        }
        Err(_) => panic!(),
    }
}
```

Verifies that the recovered suffix matches the known Base64 suffix ("Rollin' in my 5.0...").

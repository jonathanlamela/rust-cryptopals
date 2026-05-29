---
layout: default
title: "Challenge 12 — Byte-at-a-time ECB decryption (simple)"
parent: "Set 2 — EN"
nav_order: 4
permalink: /set2/en/challenge_12/
lang: en
---

# Challenge 12 — Byte-at-a-time ECB decryption (simple)

[← Previous](../challenge_11/) · [Next →](../challenge_13/) · [🇮🇹 Italiano](../../it/challenge_12/) · [Set 2 index](../)

---

## Theory

The "byte-at-a-time ECB decryption" attack is one of the most elegant oracle attacks against ECB mode. The oracle encrypts the concatenation of an attacker-controlled plaintext with a secret suffix, always using the same random key and ECB mode. The attacker knows neither the key nor the suffix, but can query the oracle with any input.

The attack works as follows: to extract the first byte of the suffix, send a plaintext of 15 bytes (one block minus one). The first encrypted block contains 15 controlled bytes plus the first suffix byte. Try all 256 possible values for the last byte: the one that produces the same first encrypted block reveals the value of the first suffix byte. Repeat with 14 bytes of padding for the second byte, and so on.

The power of this attack lies in its efficiency: for a suffix of N bytes, at most 256*N oracle queries suffice — a linear number. Compared to brute force on the entire ciphertext, this is enormously more efficient.

The `get_suffix` method in `CustomCrypter12` implements this attack completely, also handling the case where a prefix is present (absent in this challenge but present in challenge 14).

## Key concepts

- **Byte-at-a-time decryption:** extracts the suffix one byte at a time using the ECB oracle.
- **Boundary block attack:** aligns the unknown byte at the end of a known block.
- **`get_suffix`:** method that performs the complete attack to extract the secret suffix.
- **`prefix_plus_suffix_length`:** determines the total length of content added by the oracle.
- **`prefix_blocks_count`:** finds how many blocks the prefix occupies.
- **`chunks_count`:** computes the number of blocks and required fill.

## Code walkthrough

### Overview

`src/crypters/custom_crypter_12.rs` defines `CustomCrypter12` with the attack methods. `get_suffix` is the main method; it relies on `prefix_length`, `prefix_plus_suffix_length`, and `prefix_blocks_count`.

### Implementation

`prefix_blocks_count` finds how many blocks the prefix occupies:

```rust
pub fn prefix_blocks_count(&self) -> Result<usize, JlmCryptoErrors> {
    let encrypted_0 = self.base.encrypt(&[0]).unwrap();
    let encrypted_1 = self.base.encrypt(&[1]).unwrap();
    let chunks_0 = encrypted_0.chunks(Self::BLOCK_SIZE);
    let chunks_1 = encrypted_1.chunks(Self::BLOCK_SIZE);
    if let Some(result) = chunks_0.zip(chunks_1).position(|(x, y)| x != y) {
        Ok(result)
    } else {
        Err(JlmCryptoErrors::NoDifferentBlocks)
    }
}
```

Encrypts `[0]` and `[1]`: blocks containing the prefix are identical (prefix doesn't change), the block containing the input differs. The first differing block indicates where the input lives.

`get_suffix` performs the attack:

```rust
pub fn get_suffix(&self) -> Result<Vec<u8>, JlmCryptoErrors> {
    let prefix_len = self.prefix_length().unwrap();
    let suffix_len = self.prefix_plus_suffix_length().unwrap() - prefix_len;
    let (prefix_chunks_count, prefix_fill_len) = prefix_len.chunks_count();
    let mut suffix = Vec::new();
    let mut input = vec![0; prefix_fill_len + Self::BLOCK_SIZE - 1];
    let virtual_ciphertexts = (0..Self::BLOCK_SIZE)
        .map(|left_shift| self.base.encrypt(&input[left_shift..]))
        .collect::<Result<Vec<Vec<u8>>, JlmCryptoErrors>>().unwrap();
    for i in 0..suffix_len {
        let block_index = prefix_chunks_count + i / Self::BLOCK_SIZE;
        let left_shift = i % Self::BLOCK_SIZE;
        for u in 0u8..=255 {
            input.push(u);
            if virtual_ciphertexts[left_shift]
                [block_index * Self::BLOCK_SIZE..(block_index + 1) * Self::BLOCK_SIZE]
                == self.base.encrypt(&input[left_shift..]).unwrap()
                    [block_index * Self::BLOCK_SIZE..(block_index + 1) * Self::BLOCK_SIZE]
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

For each byte i of the suffix: compute `left_shift` (position within the current block) and `block_index` (which block to compare). Try all 256 values, appending each candidate to `input`, comparing the target block of the virtual ciphertext with that of the real ciphertext.

### The test

```rust
#[test]
pub fn challenge_12() {
    let oracle = CustomCrypter12::new();
    let base64_suffix = Base64::from_string(String::from(
        "Um9sbGluJyBpbiBteSA1LjAK..."
    ));
    match oracle {
        Ok(r) => {
            let input: Vec<u8> = b"A".to_vec();
            let encrypted_value = r.base.encrypt(&input).unwrap();
            assert_eq!(encrypted_value.len() % 16, 0);
            assert_eq!(base64_suffix, Base64::from_bytes(r.get_suffix().unwrap().as_slice()))
        }
        Err(_) => { panic!(); }
    }
}
```

The test verifies that the extracted suffix matches the known Base64 suffix (the rap lyrics from "Rollin' in my 5.0").

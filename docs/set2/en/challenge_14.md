---
layout: default
title: "Challenge 14 — Byte-at-a-time ECB decryption (harder)"
parent: "Set 2 — EN"
nav_order: 6
permalink: /set2/en/challenge_14/
lang: en
---

# Challenge 14 — Byte-at-a-time ECB decryption (harder)

[← Previous](../challenge_13/) · [Next →](../challenge_15/) · [🇮🇹 Italiano](../../it/challenge_14/) · [Set 2 index](../)

---

## Theory

Challenge 14 is a harder version of challenge 12: the oracle adds a random prefix (of unknown length between 1 and 10 bytes) in addition to the secret suffix. The prefix is fixed for the entire attack duration (it does not change between calls), but its length and content are unknown.

The additional difficulty is that the prefix "shifts" the boundary between controlled content and the secret suffix. Before applying the byte-at-a-time attack, the prefix length must be determined and enough padding bytes added to align the controlled content to a block boundary. Once done, the attack proceeds exactly as in challenge 12.

Determining the prefix length happens in two phases: first find the number of complete blocks occupied by the prefix (`prefix_blocks_count`), then determine exactly how many prefix bytes are in the last partial block (`prefix_length`). The latter is found incrementally: encrypt an increasing number of identical bytes until the target block stops changing — the moment it changes indicates the prefix has been "filled" to the block boundary.

## Key concepts

- **Random prefix of unknown length:** complicates block alignment compared to challenge 12.
- **`prefix_length`:** determines how many prefix bytes occupy the partial block.
- **`prefix_fill_len`:** number of bytes to add to align input to the block boundary after the prefix.
- **`chunks_count`:** method of the `USizeCrypt` trait that computes `(n_blocks, n_fill_bytes)`.
- **Prefix stability:** the prefix does not change between calls, enabling iterative analysis.
- **`CustomCrypter14`:** oracle with random prefix of random length (1–10 bytes).

## Code walkthrough

### Overview

`src/crypters/custom_crypter_14.rs` defines `CustomCrypter14` with the same attack methods as `CustomCrypter12` but with support for the variable-length prefix.

### Implementation

`prefix_length` in `CustomCrypter14`:

```rust
pub fn prefix_length(&self) -> Result<usize, JlmCryptoErrors> {
    let offset = self.prefix_blocks_count().unwrap() * Self::BLOCK_SIZE;
    let constant_block = vec![0u8; 16];
    let initial = &self.base.encrypt(&constant_block).unwrap()[offset..(offset + Self::BLOCK_SIZE)];
    for i in 0..Self::BLOCK_SIZE {
        let cur = self.base.encrypt(&constant_block[i + 1..]).unwrap();
        if cur.len() < offset + Self::BLOCK_SIZE
            || initial != &cur[offset..(offset + Self::BLOCK_SIZE)]
        {
            return Ok(i);
        }
    }
    Ok(Self::BLOCK_SIZE)
}
```

Starts with 16 input bytes (a full block). Progressively reduces the input one byte at a time from the end. When the target block changes, the number of removed bytes indicates how many prefix bytes were in the last partial block.

`get_suffix` in `CustomCrypter14` has the same logic as `CustomCrypter12`, but uses `prefix_fill_len` to correctly align the input to the block boundary after the prefix.

The `USizeCrypt::chunks_count` trait method:

```rust
fn chunks_count(self) -> (usize, usize) {
    let q = (self + 16 - 1) / 16;
    let r = q * 16 - self;
    (q, r)
}
```

`q` is the number of 16-byte blocks needed to hold `self` bytes. `r` is the number of fill bytes needed to complete the last block.

### The test

```rust
#[test]
pub fn challenge_14() {
    let oracle = CustomCrypter14::new();
    let base64_suffix = Base64::from_string(String::from(
        "Um9sbGluJyBpbiBteSA1LjAK..."
    ));
    match oracle {
        Ok(r) => {
            assert_eq!(base64_suffix, Base64::from_bytes(r.get_suffix().unwrap().as_slice()))
        }
        Err(_) => { panic!(); }
    }
}
```

As in challenge 12, the test verifies that the extracted suffix matches the expected value, even in the presence of the random prefix.

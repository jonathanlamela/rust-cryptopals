---
layout: default
title: "Challenge 14 — Byte-at-a-time ECB decryption (harder)"
parent: "Set 2 EN"
grand_parent: EN
nav_order: 6
permalink: /en/set2/challenge_14/
lang: en
---

# Challenge 14 — Byte-at-a-time ECB decryption (harder)

[← Previous](../challenge_13/) · [Next →](../challenge_15/) · [🇮🇹 Italiano](../../../it/set2/challenge_14/) · [Set 2](../) · [Home](../../)

---

## Theory

Challenge 14 is a harder variant of challenge 12. The difference is that the oracle prepends a random prefix of unknown length (1–10 bytes) before the attacker-controlled text. This prefix is the same for every oracle call, but its length is unknown.

The additional problem compared to challenge 12 is that we do not know where our controlled text starts in the block space. We must first determine the length and position of the prefix, then compensate to align our attack.

The approach is: find the "prefix blocks" by comparing ciphertexts of two inputs differing by only one byte — blocks that differ between the two ciphertexts are those influenced by our input. The number of blocks before the first differing block is the number of complete prefix blocks. The exact length of the prefix in the partial block is determined by adding filler bytes one at a time until that block stabilizes (matches a ciphertext with one fewer byte in the target block).

Once the prefix length is known, add the necessary filler to align the prefix to a block boundary, then apply the byte-at-a-time attack as in challenge 12.

## Key concepts

- **Unknown prefix**: oracle prefix length unknown but fixed per instance.
- **`prefix_blocks_count`**: method finding how many complete blocks the prefix occupies.
- **`prefix_length`**: method finding the exact prefix byte length.
- **`prefix_plus_suffix_length`**: method calculating total length of prefix + suffix.
- **Alignment padding**: bytes added by the attacker to bring the prefix to a block boundary.
- **`CustomCrypter14`**: oracle with random prefix of length 1–10 bytes plus the fixed suffix.

## Code walkthrough

### Overview

The challenge uses `src/crypters/custom_crypter_14.rs`. The logic mirrors `CustomCrypter12` but adds handling for the random prefix.

### Implementation

`prefix_blocks_count` finds the number of complete prefix blocks:

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

`prefix_length` refines the calculation by finding the exact byte count of the prefix in the last partial block:

```rust
pub fn prefix_length(&self) -> Result<usize, JlmCryptoErrors> {
    let offset = self.prefix_blocks_count().unwrap() * Self::BLOCK_SIZE;
    let constant_block = vec![0u8; Self::BLOCK_SIZE];
    let initial = &self.base.encrypt(&constant_block).unwrap()[offset..(offset + Self::BLOCK_SIZE)];
    for i in 0..Self::BLOCK_SIZE {
        let cur = self.base.encrypt(&constant_block[i + 1..]).unwrap();
        if cur.len() < offset + Self::BLOCK_SIZE || initial != &cur[offset..(offset + Self::BLOCK_SIZE)] {
            return Ok(i);
        }
    }
    Ok(Self::BLOCK_SIZE)
}
```

### The test

```rust
#[test]
pub fn challenge_14() {
    let oracle = CustomCrypter14::new();
    let base64_suffix = Base64::from_string(String::from("Um9sbGluJyBpbiBteSA1LjAK..."));
    match oracle {
        Ok(r) => {
            assert_eq!(base64_suffix, Base64::from_bytes(r.get_suffix().unwrap().as_slice()))
        }
        Err(_) => panic!(),
    }
}
```

Verifies that the suffix recovered despite the random prefix matches the known Base64 suffix.

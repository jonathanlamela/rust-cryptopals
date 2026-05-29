---
layout: default
title: "Challenge 8 — Detect AES in ECB mode"
parent: "Set 1 — EN"
nav_order: 8
permalink: /set1/en/challenge_08/
lang: en
---

# Challenge 8 — Detect AES in ECB mode

[← Previous](../challenge_07/) · [🇮🇹 Italiano](../../it/challenge_08/) · [Set 1 index](../../)

---

## Theory

The fundamental weakness of ECB mode is that identical plaintext blocks produce identical ciphertext blocks, regardless of their position in the message. This happens because each block is encrypted completely independently, with no feedback from other blocks.

This property makes ECB detectable: if an ECB ciphertext contains repeated blocks, the corresponding plaintext almost certainly contained repeated blocks under the same key. In practice, any structured data — a database, a file format, data with fixed fields — produces ECB ciphertext with repeated blocks.

The detection technique is simple: divide the ciphertext into 16-byte blocks and look for duplicates. If identical blocks exist, the ciphertext was almost certainly produced by ECB. This technique does not break the encryption (it does not recover the key or plaintext), but it identifies which mode was used — valuable information for an attack.

In Rust, the `CryptoVecChunks` trait defined in `src/cryptovec/mod.rs` provides the `contains_duplicates` method on `Vec<&[u8]>`. Duplicate detection uses the classic sort-dedup algorithm: sort the vector, remove duplicates, and if the length changes there were duplicates.

## Key concepts

- **ECB weakness:** identical plaintext blocks → identical ciphertext blocks.
- **ECB detection:** look for duplicate 16-byte blocks in the ciphertext.
- **`contains_duplicates`:** method that detects duplicates by sorting and deduplicating a vector.
- **`CryptoVecChunks`:** trait for operations on slices of byte chunks.
- **Sort-dedup:** O(n log n) algorithm for finding duplicates through sorting.
- **Not a complete attack:** detection does not recover the key, only identifies the mode.

## Code walkthrough

### Overview

The `CryptoVecChunks` trait in `src/cryptovec/mod.rs` implements `contains_duplicates` on `Vec<&[u8]>`. The test in `src/set1.rs` reads lines from a file, divides each line into 32-character hex chunks (= 16 bytes), and checks for duplicates.

### Implementation

The `CryptoVecChunks` trait:

```rust
pub trait CryptoVecChunks {
    fn contains_duplicates(&mut self) -> bool;
}

impl CryptoVecChunks for Vec<&[u8]> {
    fn contains_duplicates(&mut self) -> bool {
        let len = self.len();
        self.sort();
        self.dedup();
        len != self.len()
    }
}
```

`self.sort()` sorts the slices lexicographically — necessary for `dedup` to work (it only removes adjacent equals). `self.dedup()` removes adjacent duplicate elements. If the length after `dedup` differs from the original, duplicates existed.

### The test

```rust
#[test]
fn challenge_8() {
    let file_path = "./data/data_8.txt";
    let file = File::open(file_path).expect("Unable to read file");
    let buf_reader = BufReader::new(file);

    for line in buf_reader.lines() {
        if line.is_ok() {
            let unwrapped_line = line.unwrap();
            let line_bytes = unwrapped_line.as_bytes();
            let mut v_slices: Vec<&[u8]> = line_bytes.chunks(32).collect();
            if v_slices.contains_duplicates() {
                assert_eq!(unwrapped_line,
                    "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
                )
            }
        }
    }
}
```

The file contains hex strings, one per line. The test divides each line into 32-character chunks (each pair of hex characters represents one byte, so 32 characters = 16 bytes = one AES block). The line containing `08649af70dc06f4fd5d2d69c744cd283` repeated four times is the one encrypted in ECB. The test verifies that exactly that line is detected.

---
layout: default
title: "Challenge 8 — Detect AES in ECB mode"
parent: "Set 1 EN"
grand_parent: EN
nav_order: 8
permalink: /en/set1/challenge_08/
lang: en
---

# Challenge 8 — Detect AES in ECB mode

[← Previous](../challenge_07/) · [🇮🇹 Italiano](../../../it/set1/challenge_08/) · [Set 1](../) · [Home](../../)

---

## Theory

As discussed in challenge 7, ECB mode has a fundamental weakness: identical plaintext blocks produce identical ciphertext blocks when encrypted with the same key. This allows detection of ECB use without knowing the key, simply by searching for duplicate blocks in the ciphertext.

In practice, a ciphertext file containing structured or repetitive data (such as database records, fixed-length fields, or images) is very likely to show duplicate blocks if encrypted in ECB. Conversely, for random or unstructured data, the probability that two 16-byte blocks are identical by chance is negligible (1/2^128 for truly random plaintext blocks).

ECB detection is one of the first encrypted traffic analysis techniques used by security researchers. In the 2000s, several real implementations used ECB to encrypt session cookies, authentication tokens, and other structured data. Being able to detect ECB allowed understanding the structure of the system even without decrypting the data, and was often the first step toward more sophisticated attacks like the ECB cut-and-paste of challenge 13.

The test takes 327 lines of hex text, splits each line into 32-character hex chunks (= 16 bytes), and looks for duplicates. Only one line has duplicate chunks: that one was encrypted in ECB.

## Key concepts

- **ECB detection**: identification of ciphertext produced with ECB by searching for duplicate blocks.
- **AES block size**: 16 bytes = 32 hex characters; detection unit for duplicate search.
- **`contains_duplicates`**: `CryptoVecChunks` trait method that checks whether a slice vector has duplicate elements.
- **Sort and deduplicate**: Rust technique using `sort` + `dedup` to find duplicates in O(n log n).
- **Encrypted traffic analysis**: study of structural properties of ciphertexts without knowing the key.
- **False negative**: risk that ECB-encrypted text shows no duplicates if all corresponding plaintext blocks are distinct.

## Code walkthrough

### Overview

The challenge uses `src/cryptovec/mod.rs`, specifically the `CryptoVecChunks` trait implemented on `Vec<&[u8]>` with the `contains_duplicates` method.

### Implementation

The `contains_duplicates` method uses an efficient technique:

```rust
impl CryptoVecChunks for Vec<&[u8]> {
    fn contains_duplicates(&mut self) -> bool {
        let len = self.len();
        self.sort();
        self.dedup();
        len != self.len()
    }
}
```

Saves the original length first, then sorts the vector (required because `dedup` only removes adjacent duplicate elements), then calls `dedup` to remove duplicates. If the post-`dedup` length differs from the original, there were duplicates. This is O(n log n) for the sort rather than the naive O(n²) pairwise comparison.

In the test, each file line is split into 32-byte chunks (hex characters, not binary bytes) with `.chunks(32)`:

```rust
let mut v_slices: Vec<&[u8]> = line_bytes.chunks(32).collect();
if v_slices.contains_duplicates() {
    assert_eq!(unwrapped_line, "d880619740...");
}
```

Note: the test works on the ASCII characters of the hex representation, not the decoded bytes. This is correct because two identical hex blocks correspond to two identical encrypted blocks.

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
                    "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a")
            }
        }
    }
}
```

The test has no explicit `assert` that fails if no line has duplicates — so if the file were empty the test would pass silently. In practice, the line with duplicate blocks is identified and verified against the expected value.

---
layout: default
title: "Challenge 6 — Break repeating-key XOR"
parent: "Set 1 EN"
grand_parent: EN
nav_order: 6
permalink: /en/set1/challenge_06/
lang: en
---

# Challenge 6 — Break repeating-key XOR

[← Previous](../challenge_05/) · [Next →](../challenge_07/) · [🇮🇹 Italiano](../../../it/set1/challenge_06/) · [Set 1](../) · [Home](../../)

---

## Theory

The attack on the Vigenère cipher (repeating-key XOR) is one of the most elegant in classical cryptography. It consists of two distinct phases: first finding the key length, then breaking each single-byte sub-cipher separately.

The first phase exploits the Hamming distance, also called the bit-level edit distance. The Hamming distance between two bit strings is the number of positions where they differ. For two random plaintext blocks, the normalized Hamming distance per block length is close to 4 (on average, half the bits differ). However, when two consecutive blocks of a ciphertext are taken and their Hamming distance computed, if the block length equals the key length, both blocks were encrypted with the same key, so the Hamming distance reflects only the distance between the two plaintext blocks — which is much lower for natural language text. By seeking the block length that minimizes the normalized Hamming distance, the key length is found.

The second phase is transposition: once the key length K is known, K "columns" are constructed by taking bytes at positions 0, K, 2K, ... for the first column; bytes at positions 1, K+1, 2K+1, ... for the second; and so on. Each column is a single-byte XOR cipher, attackable with frequency analysis as in challenge 3. The complete key is obtained by combining the key bytes found for each column.

## Key concepts

- **Hamming distance**: number of bits in which two strings differ; measures bit-level dissimilarity.
- **Normalization**: dividing Hamming distance by block length to make blocks of different lengths comparable.
- **Transposition**: reorganization of the ciphertext into columns, each of which is a single-byte XOR.
- **`find_ks`**: `CryptoVec` method that finds key length by minimizing normalized Hamming distance.
- **`compute_distance_bytes`**: `CryptoVec` method computing Hamming distance between two vectors.
- **`repeating_xor_attack`**: `CryptoVec` method orchestrating the full attack: finds key and decrypts text.

## Code walkthrough

### Overview

The challenge uses `src/cryptovec/mod.rs` entirely. The main methods are `repeating_xor_attack`, `find_ks`, `compute_distance_bytes`, and `evaluate_frequency`.

### Implementation

`compute_distance_bytes` calculates the Hamming distance:

```rust
fn compute_distance_bytes(&self, bytes_b: &Vec<u8>) -> u32 {
    self.iter()
        .zip(bytes_b.iter())
        .fold(0, |acc, (&byte_a, &byte_b)| {
            acc + (byte_a ^ byte_b).count_ones()
        })
}
```

XOR of two bytes produces a value where each 1 bit indicates a difference. `count_ones()` counts the 1 bits in a `u8`, giving the number of positions where the two bytes differ. Accumulating over all bytes gives the total distance.

`find_ks` searches for the key length using six block pairs to reduce estimation variance:

```rust
fn find_ks(&self) -> Result<usize, JlmCryptoErrors> {
    let mut out_keysize: Option<usize> = None;
    let mut out_dist = f64::INFINITY;
    for ks in 2..40 {
        let chunks: Vec<&[u8]> = self.chunks(ks).collect();
        let block1 = chunks.get(0).unwrap().to_vec();
        let block2 = chunks.get(1).unwrap().to_vec();
        let block3 = chunks.get(2).unwrap().to_vec();
        let block4 = chunks.get(3).unwrap().to_vec();
        let ds = (&block1.compute_distance_bytes(&block2)
            + &block1.compute_distance_bytes(&block3)
            + &block1.compute_distance_bytes(&block4)
            + &block2.compute_distance_bytes(&block3)
            + &block2.compute_distance_bytes(&block4)
            + &block3.compute_distance_bytes(&block4)) as f64
            / (6.0 * ks as f64);
        if out_keysize.is_some() {
            if ds < out_dist { out_dist = ds; out_keysize = Some(ks); }
        } else {
            out_dist = ds; out_keysize = Some(ks);
        }
    }
    if let Some(ks) = out_keysize { Ok(ks) } else { Err(JlmCryptoErrors::UnableFindKs) }
}
```

`repeating_xor_attack` orchestrates the full attack: finds `ks`, transposes data into columns, attacks each column with `evaluate_frequency`, assembles the key, and decrypts the text.

### The test

```rust
#[test]
fn challenge_6() {
    let file_path = "./data/data_6.txt";
    // reads file, removes newlines, converts Base64 to bytes
    match bytes.repeating_xor_attack() {
        Ok(result) => assert_eq!(result, YELLOW_SUBMARINE_STRING),
        Err(_) => panic!("Test failed"),
    }
}
```

The expected result is the full text of "Play That Funky Music" by Vanilla Ice.

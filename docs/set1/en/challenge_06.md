---
layout: default
title: "Challenge 6 — Break repeating-key XOR"
parent: "Set 1 — EN"
nav_order: 6
permalink: /set1/en/challenge_06/
lang: en
---

# Challenge 6 — Break repeating-key XOR

[← Previous](../challenge_05/) · [Next →](../challenge_07/) · [🇮🇹 Italiano](../../it/challenge_06/) · [Set 1 index](../)

---

## Theory

Breaking the repeating-key XOR cipher is one of the most elegant cryptanalytic attacks in history. It combines two ideas: Hamming distance to find the key length, and frequency analysis (challenge 3) applied in parallel on each "key position".

The Hamming distance between two byte sequences is the number of bits that differ between the two sequences. It is computed by XORing corresponding bytes and counting the bits set to 1 in the result (the `popcount` operation). If the assumed key length is correct, ciphertext blocks separated by one key length have a low normalized Hamming distance — because corresponding plaintext bytes (in English) are statistically similar, and XOR with the same key byte does not increase the distance.

Once the key length K is found, the ciphertext is transposed: take bytes at positions 0, K, 2K, 3K,... (all XORed with the same key byte `key[0]`), then bytes at positions 1, K+1, 2K+1,... (all XORed with `key[1]`), and so on. Each transposed column is a single-byte XOR cipher, solved with `evaluate_frequency` (challenge 3). Assembling all discovered key bytes reconstructs the complete key.

This attack is foundational in modern cryptanalysis history. It shows that simply repeating a short key is not sufficient to guarantee security, and laid the groundwork for the study of secure stream ciphers.

## Key concepts

- **Hamming distance:** number of bits that differ between two byte sequences.
- **`popcount`:** counts set bits in a byte; `count_ones()` in Rust.
- **Estimated key length:** the K that minimizes normalized Hamming distance between ciphertext blocks.
- **Ciphertext transposition:** groups bytes by key position to obtain monoalphabetic ciphers.
- **Divide-and-conquer attack:** decomposes the problem into K instances of challenge 3.
- **Normalization by K:** Hamming distance is divided by K to compare keys of different lengths.

## Code walkthrough

### Overview

The `repeating_xor_attack` method in the `CryptoVec` trait orchestrates the attack: it first calls `find_ks` to find the best key length, then transposes the ciphertext, then calls `evaluate_frequency` on each column.

### Implementation

Hamming distance computation:

```rust
fn compute_distance_bytes(&self, bytes_b: &Vec<u8>) -> u32 {
    self.iter()
        .zip(bytes_b.iter())
        .fold(0, |acc, (&byte_a, &byte_b)| {
            acc + (byte_a ^ byte_b).count_ones()
        })
}
```

`byte_a ^ byte_b` XORs the bytes: differing bits become 1. `.count_ones()` counts the set bits — this is popcount. `.fold` accumulates the sum.

The `find_ks` method finds the optimal key length:

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

For each key length from 2 to 39, Hamming distances between all pairs of the first 4 blocks (6 pairs) are computed and averaged, normalizing by K. The K with the minimum distance is the most likely.

The `repeating_xor_attack` method assembles the complete attack:

```rust
fn repeating_xor_attack(&self) -> Result<String, JlmCryptoErrors> {
    let ks = self.find_ks().unwrap();
    let mut transposed: Vec<Vec<u8>> = vec![vec![]; ks];
    for slice in self.chunks(ks) {
        let s_len = slice.len();
        if s_len == ks {
            for i in 0..s_len {
                transposed[i].push(slice[i]);
            }
        }
    }
    let mut k_vec: Vec<u8> = Vec::new();
    for bl in transposed {
        match bl.evaluate_frequency() {
            Some((_, key, _)) => k_vec.push(key),
            None => {}
        }
    }
    if k_vec.len() > 0 {
        let repeating_key_xor_result = self.repeating_key_xor(&k_vec);
        match &str::from_utf8(&repeating_key_xor_result) {
            Ok(v) => Ok(v.to_string()),
            Err(_) => Err(JlmCryptoErrors::BreakRepeatingKeyAttackFailed),
        }
    } else {
        Err(JlmCryptoErrors::BreakRepeatingKeyAttackFailed)
    }
}
```

Transposition: for each chunk of `ks` bytes, the i-th byte goes into the i-th column. Each column is then attacked with `evaluate_frequency`. The resulting key `k_vec` is used to decrypt the original ciphertext with `repeating_key_xor`.

### The test

```rust
#[test]
fn challenge_6() {
    let file_path = "./data/data_6.txt";
    let mut file = File::open(file_path).expect("Unable to read file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Error reading file.");
    let buffer_to_string = &str::from_utf8(&buffer).unwrap().replace("\n", "");
    let input: Base64 = Base64::from_string(buffer_to_string.to_string());
    match input.to_bytes() {
        Ok(bytes) => match bytes.repeating_xor_attack() {
            Ok(result) => { assert_eq!(result, YELLOW_SUBMARINE_STRING) }
            Err(_) => panic!("Test failed"),
        },
        Err(_) => { panic!("Invalid base64 to bytes") }
    }
}
```

The file contains the ciphertext in Base64. Newlines are removed before decoding. The expected plaintext is "Play That Funky Music" by Vanilla Ice.

---
layout: default
title: "Challenge 3 — Single-byte XOR cipher"
parent: "Set 1 — EN"
nav_order: 3
permalink: /set1/en/challenge_03/
lang: en
---

# Challenge 3 — Single-byte XOR cipher

[← Previous](../challenge_02/) · [Next →](../challenge_04/) · [🇮🇹 Italiano](../../it/challenge_03/) · [Set 1 index](../../)

---

## Theory

The single-byte XOR cipher is one of the weakest ciphers in existence: a message is encrypted by XORing every byte of the plaintext with the same key byte. Despite having only 256 possible keys (values 0 to 255), this scheme is instructive because breaking it introduces frequency analysis, a statistical approach used to attack many classical ciphers.

Frequency analysis is based on the observation that in any natural language some letters appear far more often than others. In English, the letter `e` is most frequent (about 12.7%), followed by `t`, `a`, `o`, `i`, `n`. When an English text is encrypted with a single-byte XOR, the frequency distribution of letters is shifted but its shape is preserved: the most common character in the ciphertext likely corresponds to the cipher of `e`, and so on.

In the code, rather than using complex statistical analysis, a more robust approach is adopted: for every possible key (0–255), a score is computed measuring how closely the decrypted text resembles English. The score is the sum of the logarithms of the frequencies of each alphabetic letter in the candidate text. The key that maximizes this score is chosen.

This brute-force approach over a small key space (256 values) is practical and highly effective. It represents a special case of frequency scoring applied to monoalphabetic substitution ciphers. Understanding this attack is foundational: the repeating-key XOR cipher (challenges 5–6) can be reduced to a series of instances of this exact problem.

## Key concepts

- **Single-byte XOR cipher:** every plaintext byte is XORed with the same key value.
- **Frequency analysis:** exploits the non-uniform distribution of letters in natural languages.
- **Frequency score:** measures how plausible a text is based on expected letter frequencies.
- **Brute force over 256 keys:** practical approach given the tiny key space.
- **`LETTER_FREQUENCIES`:** array of expected English letter frequencies used for scoring.
- **`evaluate_score`:** method that assigns a score to a candidate byte vector.

## Code walkthrough

### Overview

The main method is `evaluate_frequency` defined in the `CryptoVec` trait in `src/cryptovec/mod.rs`. This method tries all 256 possible keys, uses `xor_single` to decrypt, and `evaluate_score` to evaluate the result.

### Implementation

English letter frequencies are defined as a constant:

```rust
pub const LETTER_FREQUENCIES: [f64; 26] = [
    8.34, 1.54, 2.73, 4.14, 12.60, 2.03, 1.92, 6.11, 6.71, 0.23, 0.87, 4.24, 2.53, 6.80, 7.70,
    1.66, 0.09, 5.68, 6.11, 9.37, 2.85, 1.06, 2.34, 0.20, 2.04, 0.06,
];
```

The 26 entries correspond to `a–z` with their respective percentage frequencies.

The `xor_single` method applies XOR with a single byte:

```rust
fn xor_single(&self, k: u8) -> Vec<u8> {
    self.iter().map(|x| x ^ k).collect()
}
```

Simple map: each byte `x` is XORed with key `k`.

The `evaluate_score` method computes text plausibility:

```rust
fn evaluate_score(&self) -> Option<f64> {
    if !self.iter().all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace()) {
        return None;
    }
    Some(self.iter().fold(0.0, |score, b| {
        if b.is_ascii_alphabetic() {
            let i = b.to_ascii_lowercase() - (b'a');
            score + LETTER_FREQUENCIES[usize::from(i)].log10()
        } else {
            score
        }
    }))
}
```

First it filters: if any byte is not a printable ASCII character or whitespace, the text is implausible and `None` is returned. Then it sums the `log10` of the frequency of each alphabetic letter. The logarithm converts multiplications into additions (since probabilities are multiplied, logs are summed), making the computation numerically stable.

The `evaluate_frequency` method orchestrates everything:

```rust
fn evaluate_frequency(&self) -> Option<(f64, u8, Vec<u8>)> {
    let mut xors_vector: Vec<(u8, Vec<u8>)> = Vec::new();
    for key in 0..=255 {
        xors_vector.push((key, self.xor_single(key)));
    }
    let filtered_map = xors_vector.iter().filter_map(|row| {
        row.1.evaluate_score().map(|score| (score, row.0, row.1.clone()))
    });
    let max_value = filtered_map.max_by(|(a, _, _), (b, _, _)| a.partial_cmp(b).unwrap());
    max_value
}
```

It builds a vector of `(key, candidate_plaintext)` pairs for every key from 0 to 255. Then `filter_map` keeps only candidates that pass `evaluate_score` (plausible ASCII texts) and computes their score. Finally `max_by` selects the candidate with the highest score. The return type `Option<(f64, u8, Vec<u8>)>` is `(score, key, plaintext)`.

### The test

```rust
#[test]
fn challenge_3() {
    let result = Hex::from_string(String::from(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
    ))
    .unwrap()
    .to_bytes()
    .unwrap()
    .evaluate_frequency()
    .unwrap();

    let stringa = String::from_utf8(result.2).unwrap();
    assert_eq!(stringa, "Cooking MC's like a pound of bacon");
}
```

The test chains: hex → bytes → `evaluate_frequency()`. The result is a tuple `(score, key, plaintext)`. `result.2` is the plaintext as `Vec<u8>`, converted to `String` with `from_utf8`. The expected value "Cooking MC's like a pound of bacon" is the reference rap song in the Cryptopals challenges.

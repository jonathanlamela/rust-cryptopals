---
layout: default
title: "Challenge 3 — Single-byte XOR cipher"
parent: "Set 1 EN"
grand_parent: EN
nav_order: 3
permalink: /en/set1/challenge_03/
lang: en
---

# Challenge 3 — Single-byte XOR cipher

[← Previous](../challenge_02/) · [Next →](../challenge_04/) · [🇮🇹 Italiano](../../../it/set1/challenge_03/) · [Set 1](../) · [Home](../../)

---

## Theory

The single-byte XOR cipher is one of the simplest possible ciphers: every byte of the message is combined with XOR using the same single key byte. Despite its simplicity, this cipher is completely insecure because it is vulnerable to frequency analysis.

Frequency analysis is based on the fact that in natural languages certain letters appear far more often than others. In English, the letter 'e' has a frequency of about 12.7%, followed by 't' (9.1%), 'a' (8.2%), and so on. If we encrypt an English text with single-byte XOR, the distribution of byte frequencies in the ciphertext will be the same as in the plaintext, just shifted cyclically by the key value. An attacker can therefore try all 256 possible keys, decrypt the text for each one, compute a score based on letter frequencies in the decrypted text, and choose the key that produces the highest score.

The score can be calculated in several ways; a common approach is to sum the log-frequencies of the letters present in the decrypted text. Using logarithms has the advantage of turning multiplication into addition and of heavily penalizing non-alphabetic characters (which often signal an incorrect decryption).

This technique — enumerating all possible keys, evaluating each decrypted text with a scoring function, and choosing the maximum — is a brute-force attack on the key space combined with a statistical oracle. It is the foundation of the attacks in challenges 4, 6, and 20.

## Key concepts

- **Single-byte XOR**: cipher that applies XOR with a single key byte to the entire message.
- **Frequency analysis**: cryptanalytic technique exploiting the non-uniform distribution of letters in natural languages.
- **Language score**: function that assigns a score to a byte array based on its plausibility as natural-language text.
- **Key space**: set of all possible key values (256 for a single byte).
- **Brute force**: attack that exhaustively enumerates the key space.
- **`evaluate_frequency`**: `CryptoVec` method that tries all 256 bytes as key and returns the highest-scoring decryption.
- **`evaluate_score`**: method that computes the sum of log-frequencies of letters in a byte array.

## Code walkthrough

### Overview

The challenge uses `src/cryptovec/mod.rs`, specifically the `evaluate_frequency`, `evaluate_score`, and `xor_single` methods of the `CryptoVec` trait.

### Implementation

`xor_single` applies XOR with a single byte:

```rust
fn xor_single(&self, k: u8) -> Vec<u8> {
    self.iter().map(|x| x ^ k).collect()
}
```

Maps every byte of the vector with XOR against key `k`. The result is a new `Vec<u8>`.

`evaluate_score` computes the plausibility of a vector as English text:

```rust
fn evaluate_score(&self) -> Option<f64> {
    if !self.iter().all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace()) {
        return None;
    }
    Some(self.iter().fold(0.0, |score, b| {
        if b.is_ascii_alphabetic() {
            let i = b.to_ascii_lowercase() - b'a';
            score + LETTER_FREQUENCIES[usize::from(i)].log10()
        } else {
            score
        }
    }))
}
```

First filters vectors containing non-printable characters — if even one byte is neither ASCII graphic nor whitespace, returns `None`. Then sums the base-10 logarithms of English frequencies for every alphabetic character. The frequency table is defined as the constant `LETTER_FREQUENCIES: [f64; 26]`.

`evaluate_frequency` orchestrates the full attack:

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

Generates all 256 possible decryptions, filters those that don't produce a valid score with `filter_map`, and returns the triple `(score, key, text)` with the maximum score.

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

The test converts the hex string to bytes, calls `evaluate_frequency`, extracts the text from the third element of the triple (`result.2`), and verifies it matches the expected plaintext.

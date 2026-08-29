---
layout: default
title: "Challenge 20 — Break fixed-nonce CTR statistically"
parent: "Set 3 EN"
grand_parent: EN
nav_order: 4
permalink: /en/set3/challenge_20/
lang: en
---

# Challenge 20 — Break fixed-nonce CTR statistically

[← Previous](../challenge_19/) · [Next →](../challenge_21/) · [🇮🇹 Italiano](../../../it/set3/challenge_20/) · [Set 3](../) · [Home](../../)

---

## Theory

Challenge 20 automates the attack from challenge 19 using the same statistical techniques as challenge 6 (break repeating-key XOR). The fixed keystream of fixed-nonce CTR messages is mathematically equivalent to a repeating-key XOR: each message at position `i` is `C[i] = P[i] XOR K[i % key_len]`.

The automated approach is transposition: collect all bytes at the same position from all messages, forming a "column vector". Each column vector is a set of bytes all encrypted with the same keystream byte. Apply letter frequency analysis to each column to find the most likely keystream byte. The complete key (keystream) is obtained by combining the bytes found for each position.

The only complication compared to challenge 6 is that messages have different lengths. The solution is to truncate all messages to the length of the shortest — some keystream coverage is lost, but it guarantees each position has the same number of samples.

This attack is fully automated and requires no manual intervention, unlike challenge 19.

## Key concepts

- **Transposition**: reorganization of ciphertexts into column vectors, one per keystream position.
- **Truncation**: reduction of all messages to the minimum length to unify the columns.
- **`evaluate_frequency`**: single-byte attack applied to each column to find the keystream byte.
- **Automated attack**: unlike challenge 19, the entire analysis is performed programmatically.
- **`repeating_key_xor`**: used to apply the found keystream to all concatenated ciphertexts.
- **Campbell texts**: the plaintexts are rap song lyrics Base64-encoded in `data_20.txt`.

## Code walkthrough

### Overview

The challenge uses `src/cryptovec/mod.rs` (`nonce_ctr_encrypt`, `evaluate_frequency`, `repeating_key_xor`) and reads from `data/data_20.txt`. The attack is fully automated in the test.

### Implementation

After fixed-nonce encryption (identical to challenge 19), find the minimum length:

```rust
let min = results.iter().map(|c| c.len()).min().unwrap();
for ciphertext in &mut results {
    ciphertext.truncate(min);
}
```

Transpose the ciphertext matrix:

```rust
let mut transposed: Vec<Vec<u8>> = vec![vec![]; min];
for string in &results {
    for i in 0..string.len() {
        let item = string[i];
        transposed[i].push(item);
    }
}
```

Apply `evaluate_frequency` to each column:

```rust
let mut k_vec: Vec<u8> = Vec::new();
for bl in transposed {
    match bl.evaluate_frequency() {
        Some((_, key, _)) => k_vec.push(key),
        None => {}
    }
}
```

Combine the found keystream with all concatenated ciphertexts:

```rust
let flat_result: Vec<u8> = results.into_iter().flat_map(|f| f).collect();
let res = flat_result.repeating_key_xor(&k_vec);
let res_plain = String::from_utf8(res).unwrap();
assert!(res_plain.contains("I'm rated"));
```

### The test

```rust
#[test]
pub fn challenge_20() {
    const BLOCK_SIZE: usize = 16;
    let key = BLOCK_SIZE.random_block();
    // file reading, encryption, transposition, attack, verification
    assert!(res_plain.contains("I'm rated"));
}
```

The test verifies that the decrypted text contains the substring "I'm rated", present in one of the source texts.

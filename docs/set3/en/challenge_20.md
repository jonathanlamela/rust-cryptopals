---
layout: default
title: "Challenge 20 — Break fixed-nonce CTR using substitutions"
parent: "Set 3 — EN"
nav_order: 4
permalink: /set3/en/challenge_20/
lang: en
---

# Challenge 20 — Break fixed-nonce CTR using substitutions

[← Previous](../challenge_19/) · [🇮🇹 Italiano](../../it/challenge_20/) · [Set 3 index](../)

---

## Theory

Challenge 20 is the automated, scaled version of challenge 19. Instead of manually analysing the ciphertexts, the statistical attack is fully automated: truncate all ciphertexts to the minimum length, transpose the ciphertext matrix to obtain "columns", apply `evaluate_frequency` to each column to find the most likely keystream byte, and XOR the entire corpus with the discovered keystream.

This approach is formally equivalent to the "break repeating-key XOR" attack of challenge 6, applied to CTR with a fixed nonce. The cyclic key is the keystream of length `min_length`: each keystream byte is the key for that "position" in the ciphertext corpus.

The practical result is remarkable: with enough ciphertexts and sufficiently long texts, it is possible to recover the keystream and read the plaintexts with good accuracy, without ever knowing the AES key. This illustrates why modern cryptographic protocols explicitly prohibit nonce reuse in CTR mode.

The `data_20.txt` file contains rap texts in Base64. The test verifies that the decrypted string contains "I'm rated" — a phrase appearing in the original texts.

## Key concepts

- **Truncation to minimum length:** all ciphertexts are cut to the length of the shortest.
- **Ciphertext matrix transposition:** groups bytes by keystream position.
- **Scaled cyclic XOR attack:** equivalent to challenge 6 applied to a ciphertext corpus.
- **`repeating_key_xor`:** used to apply the found keystream to the entire corpus.
- **`flat_map`:** transforms `Vec<Vec<u8>>` into `Vec<u8>` by concatenating all ciphertexts.
- **`data_20.txt`:** corpus of rap texts in Base64 (different from `data_19.txt`).

## Code walkthrough

### Overview

The test in `src/set3.rs` is completely self-contained: reads the file, encrypts with CTR, truncates, transposes, attacks, and verifies. It uses the same primitives as previous challenges.

### Implementation

Truncation and transposition:

```rust
let min = results.iter().map(|c| c.len()).min().unwrap();
for ciphertext in &mut results {
    ciphertext.truncate(min);
}
let mut transposed: Vec<Vec<u8>> = vec![vec![]; min];
for string in &results {
    for i in 0..string.len() {
        let item = string[i];
        transposed[i].push(item);
    }
}
```

`min` is the length of the shortest ciphertext. After truncation, every ciphertext has exactly `min` bytes. The transposition: for each position `i`, collect byte `i` from all ciphertexts into column `transposed[i]`.

Frequency attack:

```rust
let mut k_vec: Vec<u8> = Vec::new();
for bl in transposed {
    match bl.evaluate_frequency() {
        Some((_, key, _)) => k_vec.push(key),
        None => {}
    }
}
```

`evaluate_frequency` finds the most likely key byte for each column (keystream position). If no plausible candidate is found (None), that position is skipped — in practice with enough ciphertexts this rarely happens.

Decrypting the entire corpus:

```rust
let flat_result: Vec<u8> = results.into_iter().flat_map(|f| f).collect();
let res = flat_result.repeating_key_xor(&k_vec);
let res_plain = String::from_utf8(res).unwrap();
assert!(res_plain.contains("I'm rated"));
```

`flat_map` concatenates all ciphertexts into a single vector. `repeating_key_xor` with `k_vec` decrypts everything — the keystream repeats cyclically over the corpus length, but since all ciphertexts have the same length `min`, keystream bytes are correctly aligned.

### The test

```rust
#[test]
pub fn challenge_20() {
    const BLOCK_SIZE: usize = 16;
    let key = BLOCK_SIZE.random_block();
    let file_path = "./data/data_20.txt";
    let file = File::open(file_path).expect("Unable to read the file");
    let buf_reader = BufReader::new(file);
    let mut results: Vec<Vec<u8>> = Vec::new();
    for line in buf_reader.lines() {
        if line.is_ok() {
            let unwrapped_line = line.unwrap();
            let line_bytes = Base64::from_string(unwrapped_line);
            if let Ok(bytes) = line_bytes.to_bytes() {
                if let Ok(encrypt_result) = bytes.nonce_ctr_encrypt(&key, vec![0; 8]) {
                    results.push(encrypt_result);
                }
            }
        }
    }
    let min = results.iter().map(|c| c.len()).min().unwrap();
    for ciphertext in &mut results { ciphertext.truncate(min); }
    let mut transposed: Vec<Vec<u8>> = vec![vec![]; min];
    for string in &results {
        for i in 0..string.len() { transposed[i].push(string[i]); }
    }
    let mut k_vec: Vec<u8> = Vec::new();
    for bl in transposed {
        match bl.evaluate_frequency() {
            Some((_, key, _)) => k_vec.push(key),
            None => {}
        }
    }
    let flat_result: Vec<u8> = results.into_iter().flat_map(|f| f).collect();
    let res = flat_result.repeating_key_xor(&k_vec);
    let res_plain = String::from_utf8(res).unwrap();
    assert!(res_plain.contains("I'm rated"));
}
```

The test demonstrates a complete, automated attack: no manual intervention, just statistical primitives applied systematically to the ciphertext corpus.

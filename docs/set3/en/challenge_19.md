---
layout: default
title: "Challenge 19 — Break fixed-nonce CTR statistically"
parent: "Set 3 — EN"
nav_order: 3
permalink: /set3/en/challenge_19/
lang: en
---

# Challenge 19 — Break fixed-nonce CTR statistically

[← Previous](../challenge_18/) · [Next →](../challenge_20/) · [🇮🇹 Italiano](../../it/challenge_19/) · [Set 3 index](../)

---

## Theory

When CTR mode is used with the same nonce to encrypt multiple messages, all messages share the same keystream. This is exactly equivalent to reusing a one-time pad: if `C1 = P1 XOR K` and `C2 = P2 XOR K`, then `C1 XOR C2 = P1 XOR P2`. If P1 and P2 are natural language texts, the frequency distribution of `P1 XOR P2` reveals information about both.

Challenge 19 introduces this attack in "manual" form: the file `data_19.txt` contains Base64 texts, each encrypted with the same keystream (nonce = 0, same random key). The test encrypts all texts and collects them in a ciphertext vector.

The statistical attack works as follows: align all ciphertexts and look at each "column" (bytes at position i across all ciphertexts). All these bytes were XORed with the same keystream byte `K[i]`. This is exactly the challenge 3 problem (single-byte XOR): apply `evaluate_frequency` to find the most likely key byte for each position.

The result is imperfect (especially for final positions where few ciphertexts are long enough), but reveals most of the keystream and allows reading most of the plaintexts.

## Key concepts

- **Fixed nonce:** same nonce → same keystream → many-time pad vulnerability.
- **Many-time pad attack:** given K ciphertexts with the same keystream, apply frequency analysis on each column.
- **`nonce_ctr_encrypt` with zero nonce:** `vec![0; 8]` as nonce for all messages.
- **Column analysis:** groups bytes at the same position across all ciphertexts.
- **`data_19.txt`:** file with poetry texts (W.B. Yeats) in Base64.
- **Limitation:** the attack only works for positions with enough ciphertexts of sufficient length.

## Code walkthrough

### Overview

The test in `src/set3.rs` reads the file, encrypts each line with `nonce_ctr_encrypt` and zero nonce, collects the results. Verification is minimal (checks only that results exist), since the real attack requires manual analysis.

### Implementation

Encrypting all texts with the same nonce:

```rust
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
```

`vec![0; 8]` is the 8-byte all-zero nonce. The same randomly generated `key` is used for all messages. `nonce_ctr_encrypt` encrypts each message with nonce=0 and incremental counter — the keystream is identical for all.

The attack (not explicitly shown in the test but implied by the comment) would require:

```rust
// Attack pseudo-code
for i in 0..min_length {
    let column: Vec<u8> = results.iter().map(|c| c[i]).collect();
    if let Some((_, key_byte, _)) = column.evaluate_frequency() {
        keystream.push(key_byte);
    }
}
```

### The test

```rust
#[test]
pub fn challenge_19() {
    const BLOCK_SIZE: usize = 16;
    let key = BLOCK_SIZE.random_block();
    let file_path = "./data/data_19.txt";
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
    assert!(results.len() != 0);
}
```

The test verifies only that ciphertexts were produced — the vulnerability is demonstrated by the fact that all share the same keystream, fully exploited in challenge 20 with a complete automatic attack.

---
layout: default
title: "Challenge 19 — Break fixed-nonce CTR mode using substitutions"
parent: "Set 3 EN"
grand_parent: EN
nav_order: 3
permalink: /en/set3/challenge_19/
lang: en
---

# Challenge 19 — Break fixed-nonce CTR mode using substitutions

[← Previous](../challenge_18/) · [Next →](../challenge_20/) · [🇮🇹 Italiano](../../../it/set3/challenge_19/) · [Set 3](../) · [Home](../../)

---

## Theory

When multiple messages are encrypted with the same CTR key and the same nonce, the keystream is identical for all of them. This means `C[i] = P[i] XOR K` for every message `i`, where `K` is the fixed keystream. Consequently, `C[i] XOR C[j] = P[i] XOR P[j]`: the XOR of two ciphertexts is the XOR of the two plaintexts.

This is exactly the same problem as repeating-key XOR from challenge 6, applied to multiple messages instead of a single long message. An attacker observing many messages encrypted with the same keystream can apply statistical techniques to recover the keystream.

The manual approach (challenge 19) involves seeking substitutions: if we hypothesize that a certain keystream position has value `k`, then all bytes at the same position in the various messages must be `P[i][pos] = C[i][pos] XOR k`. If the hypothesis of `k` is correct, the decrypted bytes must look like plausible English characters. This is partly manual work based on linguistic intuition.

Challenge 19 shows that CTR with a fixed nonce degenerates into repeating-key XOR — the same vulnerability we already learned to exploit.

## Key concepts

- **Fixed nonce**: use of the same nonce for multiple CTR messages, producing the same keystream.
- **Many-time pad**: use of a keystream for multiple messages, the serious error equivalent to two-time pad.
- **`nonce_ctr_encrypt`**: method used to encrypt each message with the same nonce (8-byte zero vector).
- **Substitution attack**: manual guessing of keystream values based on linguistic plausibility.
- **Yeats text**: the plaintexts are lines of W.B. Yeats poems Base64-encoded in `data_19.txt`.
- **Shared keystream**: common element among all ciphertexts that links the messages.

## Code walkthrough

### Overview

The challenge uses `src/cryptovec/mod.rs` (`nonce_ctr_encrypt`) and reads messages from `data/data_19.txt`. The attack is not automated in the test: the test only verifies that encryption was performed on all messages.

### Implementation

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

Each file line is a Base64 message. It is decoded to bytes and encrypted with `nonce_ctr_encrypt` using the fixed nonce `vec![0; 8]` (8 zero bytes). The key is random but fixed for the entire session.

Since `nonce_ctr_encrypt` uses `write_u64::<LittleEndian>(count as u64)`, the 8-byte nonce plus the 8-byte little-endian counter form the 16-byte block that is AES-encrypted to produce each keystream chunk.

### The test

```rust
#[test]
pub fn challenge_19() {
    const BLOCK_SIZE: usize = 16;
    let key = BLOCK_SIZE.random_block();
    // reads file, encrypts all messages with fixed nonce
    assert!(results.len() != 0);
}
```

The test only verifies that ciphertexts were produced (the `results` vector is non-empty). Statistical analysis of the ciphertexts to recover the keystream is left as a manual exercise.

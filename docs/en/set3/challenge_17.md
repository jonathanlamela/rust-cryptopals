---
layout: default
title: "Challenge 17 — The CBC padding oracle"
parent: "Set 3 EN"
grand_parent: EN
nav_order: 1
permalink: /en/set3/challenge_17/
lang: en
---

# Challenge 17 — The CBC padding oracle

[Next →](../challenge_18/) · [🇮🇹 Italiano](../../../it/set3/challenge_17/) · [Set 3](../) · [Home](../../)

---

## Theory

The CBC padding oracle attack is one of the most famous and practically relevant cryptographic attacks ever discovered. Proposed by Vaudenay in 2002, it exploits a single binary piece of information: whether the PKCS#7 padding of a decrypted message is valid or invalid. With only this information, an attacker can decrypt any CBC message without knowing the key.

The mathematical principle is elegant. Given a ciphertext block `C[i]`, we want to find the plaintext `P[i] = D(C[i]) XOR C[i-1]`. Call `D(C[i])` the result of AES decryption of the block (without XOR with the previous block). The attack modifies `C[i-1]` one byte at a time.

To find the last byte of `P[i]`: take ciphertext block `C[i]` and modify the last byte of `C[i-1]` (call it `r`) trying all 256 values. For each value `r`, decrypt block `C[i]` with the modified `C[i-1]`. When padding is valid with value 1 (a single padding byte equal to `\x01`), we know that `D(C[i])[last byte] XOR r = 0x01`, therefore `D(C[i])[last byte] = r XOR 0x01`. From this we get `P[i][last byte] = D(C[i])[last byte] XOR C[i-1][last byte]`.

To find the second-to-last byte, set the last byte of the modified `C[i-1]` so that padding is `\x02\x02` (two padding bytes), and iterate over the second-to-last byte. And so on for all 16 bytes of the block.

## Key concepts

- **Padding oracle**: system that reveals whether padding is valid (without revealing the plaintext).
- **`D(C[i])`**: result of AES block decryption without XOR with the previous block.
- **Iterative attack**: byte-by-byte recovery of plaintext by modifying the previous ciphertext block.
- **`CustomCrypter17`**: struct providing tokens to decrypt and encryption/decryption functions.
- **Padding propagation**: modification of the previous block to induce specific padding patterns.
- **`ssl_cbc_decrypt` with `Some(true)`**: decryption that validates padding and returns error if invalid — the information exploited by the oracle.

## Code walkthrough

### Overview

The challenge uses `src/crypters/custom_crypter_17.rs` for tokens and `src/cryptovec/mod.rs` for CBC encryption and decryption. The attack is implemented directly in the test in `src/set3.rs`.

### Implementation

The heart of the attack is the double nested loop in the test. For each ciphertext block, and for each byte within the block (from last to first):

```rust
for (block_index, block) in chunks.enumerate() {
    let block_offset = block_index * BLOCK_SIZE;
    for i in (0..BLOCK_SIZE).rev() {
        let padding = (BLOCK_SIZE - i) as u8;
        let t = [(padding - 1) ^ padding];
        let xor_res = prev[i + 1..].to_vec().xor_single(t[0]);
        prev[i + 1..].copy_from_slice(&xor_res);
        for u in 0u8..=255 {
            prev[i] ^= u;
            let value_decrypted = block.to_vec().ssl_cbc_decrypt(&key, &prev, Some(true));
            if value_decrypted.is_ok()
                && (i < BLOCK_SIZE - 1 || {
                    prev[i - 1] ^= 1;
                    let result = block.to_vec().ssl_cbc_decrypt(&key, &prev, Some(true));
                    prev[i - 1] ^= 1;
                    result.is_ok()
                })
            {
                let new_content = padding ^ u;
                cleartext_encrypted[block_offset + i] = new_content;
                break;
            }
            prev[i] ^= u;
        }
    }
    prev = block.to_vec();
}
```

The additional check `prev[i - 1] ^= 1` for the case `i == BLOCK_SIZE - 1` prevents false positives: when searching for the last byte value, a value `u` might produce valid padding `\x02\x02` instead of `\x01`. By modifying the second-to-last byte and verifying the padding does not change, we confirm it is truly `\x01` padding.

### The test

The test encrypts a token with random key and IV, applies the padding oracle attack to recover the plaintext, then verifies the recovered text matches the original text decrypted with the correct key.

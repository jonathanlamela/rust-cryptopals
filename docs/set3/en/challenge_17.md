---
layout: default
title: "Challenge 17 — The CBC padding oracle"
parent: "Set 3 — EN"
nav_order: 1
permalink: /set3/en/challenge_17/
lang: en
---

# Challenge 17 — The CBC padding oracle

[Next →](../challenge_18/) · [🇮🇹 Italiano](../../it/challenge_17/) · [Set 3 index](../)

---

## Theory

The CBC padding oracle attack is one of the most important and practical cryptographic attacks ever discovered, published by Vaudenay in 2002. It allows decrypting any CBC ciphertext without knowing the key, using only the oracle's response ("valid padding" or "invalid padding").

The mechanism is based on CBC's structure: to decrypt block C[i], compute `D[i] = AES_Decrypt(C[i])`, then the plaintext is `P[i] = D[i] XOR C[i-1]`. If C[i-1] is modified and the modified block is sent to the oracle, the value of `D[i]` can be deduced.

To discover the last byte of D[i], modify the last byte of C[i-1] through all 256 possible values. The value `u` that produces valid padding (i.e., `\x01`) satisfies `D[i][15] XOR (C[i-1][15] XOR u) = 1`, from which `D[i][15] = 1 XOR C[i-1][15] XOR u`. Knowing `D[i][15]`, recover `P[i][15] = D[i][15] XOR C[i-1][15]`.

Proceed for the second-to-last byte, setting padding to `\x02\x02`, and so on. Total cost is at most `256 * BLOCK_SIZE * N_BLOCKS` oracle queries — feasible for reasonably-sized ciphertexts.

This attack has had enormous implications for cryptographic practice. It led to the deprecation of CBC with PKCS#7 padding without authentication and to the adoption of authenticated encryption (AEAD).

## Key concepts

- **Padding oracle:** system that reveals whether a ciphertext's padding is valid.
- **Vaudenay's attack:** CBC decryption using only padding feedback.
- **`D[i]`:** raw output of AES_Decrypt on block i (before XOR with the previous block).
- **Previous block manipulation:** changing C[i-1] predictably changes P[i].
- **`ssl_cbc_decrypt` as oracle:** returns `Err(InvalidPadding)` for invalid padding.
- **`CustomCrypter17`:** class with predefined tokens to decrypt.

## Code walkthrough

### Overview

`src/crypters/custom_crypter_17.rs` defines `CustomCrypter17` with an array of 10 Base64 tokens. The test in `src/set3.rs` implements the complete padding oracle attack.

### Implementation

The padding oracle attack loop in the test:

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

The outer loop iterates over blocks. For each block, the inner loop iterates over bytes from right to left (`rev()`). For each position i: compute target padding `padding = BLOCK_SIZE - i`; adjust already-found bytes to produce the correct padding (`xor_res`); try all 256 values of `u` by XORing `prev[i]` until `ssl_cbc_decrypt` returns `Ok`. The special check for `i == BLOCK_SIZE - 1` (last byte) handles the `\x01` padding ambiguity — verify that `prev[i-1] ^= 1` also does not break validity.

### The test

```rust
#[test]
pub fn challenge_17() {
    let crypter = CustomCrypter17::new().unwrap();
    const BLOCK_SIZE: usize = 16;
    let key = BLOCK_SIZE.random_block();
    let iv = BLOCK_SIZE.random_block();
    let clear_value = Base64::from_string(crypter.get_all_tokens().get(8).unwrap().to_string());
    let clear_bytes = clear_value.to_bytes().unwrap();
    let encrypted_value = clear_bytes.to_vec().ssl_cbc_encrypt(&key, &iv, Some(false));
    // ... attack ...
    assert_eq!(decrypted_first.unwrap(), decrypted_second.unwrap());
}
```

The test uses token 8 (`ollin' in my five point oh`). It encrypts with a random key, performs the padding oracle attack, and verifies that the recovered plaintext equals the original decrypted plaintext.

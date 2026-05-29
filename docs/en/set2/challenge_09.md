---
layout: default
title: "Challenge 9 — Implement PKCS#7 padding"
parent: "Set 2 EN"
grand_parent: EN
nav_order: 1
permalink: /en/set2/challenge_09/
lang: en
---

# Challenge 9 — Implement PKCS#7 padding

[Next →](../challenge_10/) · [🇮🇹 Italiano](../../../it/set2/challenge_09/) · [Set 2](../) · [Home](../../)

---

## Theory

Block ciphers like AES require the plaintext to have an exact length that is a multiple of the block size (16 bytes for AES-128). In practice, messages rarely have such precise lengths. Padding is the mechanism that resolves this problem: it adds extra bytes at the end of the message to bring it to the required length.

PKCS#7 (Public Key Cryptography Standards #7) is the most commonly used padding scheme. The rule is simple and ingenious: if the message needs P bytes of padding (with 1 ≤ P ≤ block_size), exactly P bytes are added, each with the value P. If the message is already exactly a multiple of the block size, an entire block of padding is added with all bytes set to the value block_size (16 for AES). This second case is necessary to ensure padding can always be removed unambiguously: the receiver always reads the last byte, interprets its value as the number of padding bytes, and strips them.

Examples:
- "YELLOW SUBMARINE" (16 bytes) → "YELLOW SUBMARINE\x10\x10...\x10" (32 bytes, 16 padding bytes with value 16)
- "YELLOW SUBMARIN" (15 bytes) → "YELLOW SUBMARIN\x01" (16 bytes, 1 padding byte with value 1)
- "HELLO" (5 bytes) with block 8 → "HELLO\x03\x03\x03" (8 bytes, 3 padding bytes with value 3)

Padding validation is equally important: during decryption one must check that the padding bytes all equal their value. If the padding is invalid, the message is corrupted or tampered. This verification is the foundation of the "padding oracle attack" in challenge 17.

## Key concepts

- **PKCS#7**: padding scheme that adds P bytes of value P to bring the message to a multiple of block size.
- **AES block**: 16 bytes; padding always brings to a multiple of 16.
- **Mandatory padding**: even messages already a multiple of the block size receive a full padding block.
- **`pad`**: `CryptoVec` method that adds PKCS#7 padding in-place.
- **`unpad`**: `CryptoVec` method that removes PKCS#7 padding after validating it.
- **`check_padding_valid`**: method that validates padding without removing it.

## Code walkthrough

### Overview

The challenge uses `src/cryptovec/mod.rs`, specifically the `pad`, `unpad`, and `check_padding_valid` methods of the `CryptoVec` trait implemented on `Vec<u8>`.

### Implementation

`pad` adds PKCS#7 padding:

```rust
fn pad(&mut self, k: u8) -> Result<bool, JlmCryptoErrors> {
    if k < 2 {
        return Err(JlmCryptoErrors::PKCS7PaddingFailed);
    }
    let p = k - (self.len() % k as usize) as u8;
    for _ in 0..p {
        self.push(p);
    }
    Ok(true)
}
```

Computes the number of padding bytes needed: `k - (len % k)`. If `len % k == 0`, the result is `k` (a full padding block). If `len % k == r`, the result is `k - r`. Then adds exactly `p` bytes each with value `p`.

`check_padding_valid` verifies the padding is correct:

```rust
fn check_padding_valid(&self, k: u8) -> Result<bool, JlmCryptoErrors> {
    if k < 2 { return Err(JlmCryptoErrors::InvalidPadding); }
    if self.is_empty() || self.len() % k as usize != 0 {
        return Err(JlmCryptoErrors::InvalidPadding);
    }
    let padding = self[self.len() - 1];
    if !(1 <= padding && padding <= k) {
        return Err(JlmCryptoErrors::InvalidPadding);
    }
    let is_valid = self[self.len() - padding as usize..]
        .iter()
        .all(|&b| b == padding);
    if is_valid { Ok(true) } else { Err(JlmCryptoErrors::InvalidPadding) }
}
```

Reads the last byte as the padding value, verifies it is in the range [1, k], then checks that all the last `padding` bytes have the same value.

### The test

```rust
#[test]
fn challenge_9() {
    let size = 20;
    let mut string_to_pad = b"YELLOW SUBMARINE".to_vec();
    string_to_pad.pad(size).unwrap();
    assert_eq!(
        &string_to_pad,
        [89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4].as_ref()
    )
}
```

"YELLOW SUBMARINE" is 16 bytes. With block size 20, the required padding is `20 - (16 % 20) = 4`. So 4 bytes of value 4 (0x04) are added. The test verifies the expected result byte by byte.

---
layout: default
title: "Challenge 9 — Implement PKCS#7 padding"
parent: "Set 2 — EN"
nav_order: 1
permalink: /set2/en/challenge_09/
lang: en
---

# Challenge 9 — Implement PKCS#7 padding

[Next →](../challenge_10/) · [🇮🇹 Italiano](../../it/challenge_09/) · [Set 2 index](../)

---

## Theory

Block ciphers like AES operate on fixed-size blocks (16 bytes for AES). When the plaintext is not an exact multiple of the block size, padding bytes must be added to complete the last block. The PKCS#7 (Public-Key Cryptography Standards #7) standard defines a simple, unambiguous padding scheme.

The PKCS#7 scheme works as follows: if N bytes of padding are needed (with N between 1 and the block size), exactly N bytes are added, each with the value N. If the message is already a multiple of the block size, an entire padding block is added with all bytes equal to the block size (for example, 16 bytes with value 0x10 for a 16-byte block). This guarantees that padding is always present and removable unambiguously.

To remove padding, read the last byte of the decrypted text — its value indicates how many padding bytes were added. Verify that the last N bytes all have the value N, then remove them. If the verification fails, the padding is invalid (this is critical for the challenge 17 attack).

PKCS#7 is standard in TLS, S/MIME, and almost all cryptographic protocols that use block ciphers. Its correct implementation is foundational: a non-standard padding implementation is a common source of vulnerabilities.

## Key concepts

- **PKCS#7:** padding scheme that adds N bytes with value N to bring the message to a block size multiple.
- **Padding invariant:** padding is always present, even if the message is already block-aligned.
- **Deterministic unpadding:** the last byte indicates how much padding to remove.
- **Padding validation:** all last N bytes must have the value N.
- **`JlmCryptoErrors::PKCS7PaddingFailed`:** error returned if k < 2.
- **`JlmCryptoErrors::InvalidPadding`:** error returned if padding is invalid.

## Code walkthrough

### Overview

The `pad`, `unpad`, and `check_padding_valid` methods are defined in the `CryptoVec` trait in `src/cryptovec/mod.rs`. The test in `src/set2.rs` verifies padding on "YELLOW SUBMARINE" to 20 bytes.

### Implementation

The `pad` method:

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

`k` is the block size. `self.len() % k as usize` is the number of bytes already in the last partial block. `p = k - (self.len() % k)` is the number of padding bytes needed. If the message is already aligned, `self.len() % k == 0` and `p = k` — an entire padding block is added.

The `check_padding_valid` method:

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
    let is_valid = self[self.len() - padding as usize..].iter().all(|&b| b == padding);
    if is_valid { Ok(true) } else { Err(JlmCryptoErrors::InvalidPadding) }
}
```

Verifies that the vector is non-empty, is a multiple of k, that the last byte is in the range `[1, k]`, and that all last `padding` bytes have the value `padding`.

The `unpad` method:

```rust
fn unpad(&mut self, k: u8) -> Result<bool, JlmCryptoErrors> {
    if !self.check_padding_valid(k)? {
        return Err(JlmCryptoErrors::InvalidPadding);
    }
    let len_new = self.len() - self[self.len() - 1] as usize;
    self.truncate(len_new);
    Ok(true)
}
```

After validation, it computes the new length and truncates the vector.

### The test

```rust
#[test]
fn challenge_9() {
    let size = 20;
    let mut string_to_pad = b"YELLOW SUBMARINE".to_vec();
    string_to_pad.pad(size).unwrap();
    assert_eq!(
        &string_to_pad,
        [89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4,].as_ref()
    )
}
```

"YELLOW SUBMARINE" is 16 bytes. Padding to 20 bytes (k=20) requires 4 padding bytes. PKCS#7 padding adds 4 bytes with value 4 (0x04). The expected array shows exactly this.

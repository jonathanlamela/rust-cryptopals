---
layout: default
title: "Challenge 15 — PKCS#7 padding validation"
parent: "Set 2 EN"
grand_parent: EN
nav_order: 7
permalink: /en/set2/challenge_15/
lang: en
---

# Challenge 15 — PKCS#7 padding validation

[← Previous](../challenge_14/) · [Next →](../challenge_16/) · [🇮🇹 Italiano](../../../it/set2/challenge_15/) · [Set 2](../) · [Home](../../)

---

## Theory

PKCS#7 padding validation is a critical operation in any block cipher implementation. A correct implementation must verify that: the final byte of the decrypted message is a valid padding value (between 1 and block_size), and all the last N bytes have the same value N.

If the padding is invalid, the system must return an error. The temptation to silently ignore padding errors, or to handle them without returning an error, is the cause of the famous "CBC padding oracle attack" (challenge 17): if the system responds differently to valid vs. invalid padding, an attacker can use these different responses as an oracle to decrypt the message.

Challenge 15 builds exactly the padding validation function that will be exploited in challenge 17. Understanding why this function is correct — and why an implementation that returns the unmodified message instead of an error would be vulnerable — is fundamental.

A note on the distinction: `check_padding_valid` validates without modifying; `unpad` removes padding after validating. Both use the same validation algorithm but with different side effects.

## Key concepts

- **Padding oracle**: vulnerability in which the padding error behavior reveals information about the plaintext.
- **`check_padding_valid`**: method that validates PKCS#7 padding returning `Ok(true)` or `Err(InvalidPadding)`.
- **`unpad`**: method that removes PKCS#7 padding after validating it.
- **Padding error**: condition indicating the message is corrupted or padding was not applied correctly.
- **Padding byte**: the last byte of the message indicates how many padding bytes follow (including itself).
- **Side channel**: unintentional information channel that can be exploited by an attacker.

## Code walkthrough

### Overview

The challenge uses exclusively `src/cryptovec/mod.rs`, methods `check_padding_valid` and `unpad`.

### Implementation

`check_padding_valid` full logic:

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

Note that the function always returns `Result`: `Ok(true)` for valid padding, `Err` for any form of invalid padding. There is no "silent" path that returns the unmodified message.

`unpad` calls `check_padding_valid` before truncating:

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

### The test

```rust
#[test]
pub fn challenge_15() {
    let str1 = String::from("ICE ICE BABY\x04\x04\x04\x04");
    let str2 = String::from("ICE ICE BABY\x05\x05\x05\x05");
    let str3 = String::from("ICE ICE BABY\x05\x05\x05\x05");
    let mut str1_vec = str1.as_bytes().to_vec();
    let str2_vec = str2.as_bytes().to_vec();
    let str3_vec = str3.as_bytes().to_vec();
    assert_eq!(str1_vec.check_padding_valid(16).unwrap(), true);
    assert_eq!(str2_vec.check_padding_valid(16).is_err(), true);
    assert_eq!(str3_vec.check_padding_valid(16).is_err(), true);
    let _ = str1_vec.unpad(16);
    assert_eq!(String::from_utf8(str1_vec).unwrap(), "ICE ICE BABY");
}
```

`str1` has valid padding: 4 bytes with value 4. `str2` and `str3` have invalid padding: bytes have value 5 but "ICE ICE BABY" is only 12 bytes, so `12 + 5 = 17 > 16` and the padding is not a multiple of the block — returns error. After `unpad`, `str1` becomes "ICE ICE BABY".

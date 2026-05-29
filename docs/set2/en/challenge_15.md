---
layout: default
title: "Challenge 15 — PKCS#7 padding validation"
parent: "Set 2 — EN"
nav_order: 7
permalink: /set2/en/challenge_15/
lang: en
---

# Challenge 15 — PKCS#7 padding validation

[← Previous](../challenge_14/) · [Next →](../challenge_16/) · [🇮🇹 Italiano](../../it/challenge_15/) · [Set 2 index](../)

---

## Theory

PKCS#7 padding validation is more subtle than it appears. A naïve implementation checks only the last byte and removes that many bytes without verifying that all padding bytes have the correct value. This error creates a vulnerability: an attacker can inject invalid padding bytes that are accepted, altering the plaintext.

Correct validation requires three checks: (1) the vector is non-empty and its length is a multiple of the block size; (2) the last byte has a value between 1 and the block size; (3) all last N bytes (where N is the value of the last byte) have the value N.

Challenge 17 (padding oracle) exploits exactly this validation: the oracle accepts the ciphertext and returns whether the padding is valid, allowing the attacker to deduce the plaintext byte by byte.

The test in this challenge demonstrates three cases: valid padding (`\x04\x04\x04\x04`), padding with wrong value (`\x05\x05\x05\x05` at the end of different text), and correct padding removal.

## Key concepts

- **Strict padding validation:** all last N bytes must have the value N.
- **`check_padding_valid`:** returns `Ok(true)` or `Err(InvalidPadding)`.
- **`unpad`:** removes padding after validation.
- **Timing attacks:** an incorrect implementation that exits early can reveal information through response times.
- **Padding oracle:** the result of `check_padding_valid` is the oracle used in challenge 17.
- **`JlmCryptoErrors::InvalidPadding`:** error type used to signal invalid padding.

## Code walkthrough

### Overview

The `check_padding_valid` and `unpad` methods are in the `CryptoVec` trait in `src/cryptovec/mod.rs`. Already described in challenge 9, they are tested more thoroughly here.

### Implementation

`check_padding_valid` verifies that the vector is non-empty and is a multiple of k, that the last byte `padding` is in `[1, k]`, and that all bytes `self[self.len() - padding..]` have value `padding`.

An important detail: the method returns `Err` for invalid padding, not `Ok(false)`. This enables the use of the `?` operator for error propagation and makes the padding error semantics explicit — critical for the padding oracle attack in challenge 17.

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

`str1` has valid padding: 4 bytes with value 4. The string is 16 bytes total (12 + 4), a multiple of 16. `str2` and `str3` have 4 bytes with value 5, but the padding bytes have value 5 when value 4 is expected. Both fail. After `unpad`, `str1_vec` becomes "ICE ICE BABY".

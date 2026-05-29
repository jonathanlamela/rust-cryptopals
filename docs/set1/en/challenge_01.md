---
layout: default
title: "Challenge 1 — Convert hex to base64"
parent: "Set 1 — EN"
nav_order: 1
permalink: /set1/en/challenge_01/
lang: en
---

# Challenge 1 — Convert hex to base64

[Next →](../challenge_02/) · [🇮🇹 Italiano](../../it/challenge_01/) · [Set 1 index](../../)

---

## Theory

Encoding is a fundamental tool in modern cryptography: it does not encrypt data, but represents it in a different format for transmission or storage. The two most common encodings for binary data are hexadecimal notation (hex) and Base64.

Hexadecimal notation represents each byte as two ASCII characters chosen from the set `0–9, a–f`. A byte with decimal value 255 becomes `ff`. This representation is intuitive for programmers because the correspondence with bits is direct: each nibble (4 bits) maps to a single hex character. A sequence of N bytes therefore requires exactly 2N hex characters.

Base64 is a more compact encoding: it represents each group of 3 bytes (24 bits) as 4 ASCII characters chosen from an alphabet of 64 symbols (`A–Z`, `a–z`, `0–9`, `+`, `/`). The expansion ratio is 4/3, lower than hex's 2/1. Padding with `=` aligns the output when the number of bytes is not a multiple of 3. Base64 is ubiquitous: it appears in email (MIME), X.509 certificates, session cookies, and REST APIs transporting binary data.

Cryptopals challenge 1 is deliberately simple: convert a hex string to Base64, demonstrating correct handling of data representation layers. This exercise is foundational because all subsequent challenges use both encodings extensively. A conversion error at the start would produce incomprehensible output that is hard to diagnose.

In Rust, error handling via `Result<T, E>` makes every potentially failing conversion step explicit. This clarity, absent in many dynamic languages, helps reason about edge cases such as odd-length hex strings or invalid characters.

## Key concepts

- **Hex (hexadecimal):** byte encoding as `0–9a–f` character pairs; 2 characters per byte.
- **Base64:** encoding of 3 bytes into 4 ASCII characters; used to carry binary data in textual contexts.
- **Nibble:** half a byte (4 bits); one hex character corresponds to one nibble.
- **Base64 padding:** `=` character appended to align output to multiples of 4 characters.
- **`Result<T, E>`:** Rust type for explicit success/error handling without exceptions.
- **Representation invariant:** same underlying bytes, different surface encoding.

## Code walkthrough

### Overview

The challenge involves two modules: `src/hex/mod.rs` (the `Hex` struct) and `src/base64/mod.rs` (the `Base64` struct). The test in `src/set1.rs` creates a `Hex` from a string, converts it to `Base64`, and compares the result to the expected value.

### Implementation

The `Hex` struct is a newtype around `String`:

```rust
pub struct Hex(pub String);
```

The `from_string` constructor validates input before wrapping it:

```rust
pub fn from_string(s: String) -> Result<Hex, JlmCryptoErrors> {
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(JlmCryptoErrors::InvalidHEXValue);
    }
    if s.len() % 2 != 0 {
        return Err(JlmCryptoErrors::InvalidHEXValue);
    }
    Ok(Hex(s))
}
```

Validation has two steps: first it checks every character is a valid hex digit with `is_ascii_hexdigit()`, then it verifies even length (each byte requires exactly 2 hex characters). Either failing check returns `JlmCryptoErrors::InvalidHEXValue`.

The `to_bytes` method converts the hex string to a byte vector:

```rust
pub fn to_bytes(&self) -> Result<Vec<u8>, JlmCryptoErrors> {
    let mut result = Vec::new();
    for i in (0..self.0.len()).step_by(2) {
        let byte_str = &self.0[i..i + 2];
        match u8::from_str_radix(byte_str, 16) {
            Ok(byte) => result.push(byte),
            Err(_) => return Err(JlmCryptoErrors::InvalidHEXToBytesConversion),
        }
    }
    Ok(result)
}
```

This iterates over the string in steps of 2, takes each pair with `&self.0[i..i+2]`, and converts it to `u8` using `u8::from_str_radix(byte_str, 16)`. Base 16 corresponds to hexadecimal. Any parsing error is propagated as `Err`.

The main method for this challenge is `to_base64` on `Hex`:

```rust
pub fn to_base64(&self) -> Result<Base64, JlmCryptoErrors> {
    match &self.to_bytes() {
        Ok(v) => {
            const BASE64_CHARS: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut result = String::new();
            for chunk in v.chunks(3) {
                let b1 = chunk[0];
                let b2 = if chunk.len() > 1 { chunk[1] } else { 0 };
                let b3 = if chunk.len() > 2 { chunk[2] } else { 0 };
                let n = ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);
                result.push(BASE64_CHARS[((n >> 18) & 63) as usize] as char);
                result.push(BASE64_CHARS[((n >> 12) & 63) as usize] as char);
                if chunk.len() > 1 {
                    result.push(BASE64_CHARS[((n >> 6) & 63) as usize] as char);
                } else { result.push('='); }
                if chunk.len() > 2 {
                    result.push(BASE64_CHARS[(n & 63) as usize] as char);
                } else { result.push('='); }
            }
            Ok(Base64::from_string(result))
        }
        Err(_) => Err(JlmCryptoErrors::InvalidHEXToBase64Conversion),
    }
}
```

It first converts bytes from `to_bytes()`. Then it iterates in 3-byte chunks: the three bytes are packed into a 32-bit integer using bitwise shifts and OR. The 24 bits are extracted into four 6-bit groups using shifts and the mask `& 63` (`0b111111`), each used as an index into the Base64 alphabet. If the chunk has fewer than 3 bytes, the padding character `=` replaces missing characters.

### The test

```rust
#[test]
fn challenge_1() {
    assert_eq!(
        Hex::from_string(String::from(
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        ))
        .unwrap()
        .to_base64()
        .unwrap(),
        Base64::from_string(String::from(
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        ))
    );
}
```

The test builds a `Hex` from the supplied string, calls `.to_base64()`, and compares the result to the expected `Base64` using `PartialEq`. The `.unwrap()` calls convert errors to panics — appropriate in tests. The hex string decodes to ASCII "I'm killing your brain like a poisonous mushroom", the famous Cryptopals opening phrase.

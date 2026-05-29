---
layout: default
title: "Challenge 1 — Convert hex to Base64"
parent: "Set 1 EN"
grand_parent: EN
nav_order: 1
permalink: /en/set1/challenge_01/
lang: en
---

# Challenge 1 — Convert hex to Base64

[Next →](../challenge_02/) · [🇮🇹 Italiano](../../../it/set1/challenge_01/) · [Set 1](../) · [Home](../../)

---

## Theory

Hexadecimal (hex) encoding and Base64 encoding are two of the most widely used binary representation systems in computing and cryptography. Hex notation uses sixteen symbols (0–9, a–f) to represent every four-bit nibble: each byte is expressed as a pair of hex characters, giving exactly two characters per byte. This format is developer-readable, compact, and losslessly reversible.

Base64, by contrast, was designed to carry arbitrary binary data through channels that accept only seven-bit ASCII text, such as SMTP email or URLs. The algorithm takes three bytes (24 bits) at a time and splits them into four groups of six bits each. Every six-bit group is then mapped onto one of the 64 characters in the Base64 vocabulary: A–Z (0–25), a–z (26–51), 0–9 (52–61), + (62), and / (63). If the number of original bytes is not divisible by three, one or two `=` padding characters are appended to complete the final group of four characters. The result is a string roughly 33% longer than the original data, yet fully compatible with any system that accepts ASCII text.

Converting from hex to Base64 requires two steps: first the hex character pairs are converted to bytes, then Base64 encoding is applied to those bytes. In Rust, this chain is particularly elegant thanks to the type system and method chaining. The entire operation is deterministic: given the same input bytes, Base64 encoding will always produce the same string.

Understanding these two encodings is fundamental to practical cryptography, because almost every security protocol — TLS, JWT, SSH, PGP — uses hex or Base64 to serialize keys, certificates, and encrypted data.

## Key concepts

- **Hexadecimal notation**: base-16 positional system using 0–9 and a–f to represent 4-bit nibbles.
- **Base64**: encoding that maps 3 bytes (24 bits) into 4 ASCII characters using an alphabet of 64 safe symbols.
- **Base64 padding**: `=` character appended at the end to bring output to a multiple of 4 characters.
- **Nibble**: half a byte (4 bits), the base unit of hex representation.
- **Binary representation**: encoding does not alter the underlying data, only its textual representation.
- **`Hex` struct**: Rust type wrapping a hex string with validation and conversion methods.
- **`Base64` struct**: Rust type wrapping a Base64 string with constructors from strings and byte slices.

## Code walkthrough

### Overview

The challenge involves two main modules: `src/hex/mod.rs` defining the `Hex` struct, and `src/base64/mod.rs` defining the `Base64` struct. The test in `src/set1.rs` links the two via the method chain `from_string` → `to_base64`.

### Implementation

The entry point is `Hex::from_string`, which accepts a `String` and validates its content:

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

The method uses `.chars().all()` to ensure every character is a valid hex digit (0–9, a–f, A–F). It also checks length parity, required because each byte needs exactly two hex characters. If both validations pass, it builds the `Hex(s)` value — a newtype pattern wrapping the raw `String`.

`to_base64` orchestrates the full conversion:

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
                } else {
                    result.push('=');
                }
                if chunk.len() > 2 {
                    result.push(BASE64_CHARS[(n & 63) as usize] as char);
                } else {
                    result.push('=');
                }
            }
            Ok(Base64::from_string(result))
        }
        Err(_) => Err(JlmCryptoErrors::InvalidHEXToBase64Conversion),
    }
}
```

It first calls `to_bytes()` to convert the hex pairs into bytes, then processes the bytes in chunks of 3: three bytes are combined into a 32-bit integer via shifts and bitwise OR, and four 6-bit indices are extracted with `& 63` masks. Each index indexes the `BASE64_CHARS` array. If the final chunk has fewer than 3 bytes, missing bytes are treated as zero and the corresponding characters are replaced with `=`.

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

The test creates a `Hex` from the input string, calls `.to_base64()`, and compares the result with the expected Base64 value using `assert_eq!`. Both sides implement `PartialEq` for direct comparison. The hex string decodes the ASCII text "I'm killing your brain like a poisonous mushroom".

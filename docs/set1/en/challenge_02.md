---
layout: default
title: "Challenge 2 — Fixed XOR"
parent: "Set 1 — EN"
nav_order: 2
permalink: /set1/en/challenge_02/
lang: en
---

# Challenge 2 — Fixed XOR

[← Previous](../challenge_01/) · [Next →](../challenge_03/) · [🇮🇹 Italiano](../../it/challenge_02/) · [Set 1 index](../../)

---

## Theory

The XOR (exclusive OR) operation is the most important binary operation in cryptography. Given two bits, XOR returns 1 if and only if the bits differ; it returns 0 if they are the same. This simple rule has highly useful properties: it is self-inverse (`a XOR b XOR b = a`), commutative, and associative. Self-inversion means the same operation serves both encryption and decryption, greatly simplifying implementation.

Bitwise XOR between two equal-length byte sequences produces a third sequence where each byte is the XOR of the corresponding bytes. If one operand is secret (the key), the result is unintelligible to anyone who does not know the key. If both operands are known, XOR reveals the other — this is the principle behind many cryptographic attacks.

In the Cryptopals context, this challenge serves as a technical exercise but anticipates critical concepts: XOR over equal-length sequences is the foundation of the one-time pad (OTP), the only theoretically unbreakable cipher. The OTP requires the key to be at least as long as the message, completely random, and used only once. If these conditions are not met — as in the repeating-key XOR cipher of challenges 5 and 6 — security collapses.

XOR also underpins feedback functions in block ciphers (CBC uses XOR between successive blocks) and stream ciphers (CTR mode uses XOR between keystream and plaintext). Understanding how XOR works at the byte level is therefore a prerequisite for all subsequent challenges.

In Rust, `Vec<u8>` is the natural type for byte sequences, and the `CryptoVec` trait defines cryptographic operations on them in an ergonomic and safe manner.

## Key concepts

- **XOR (exclusive OR):** bitwise operation; `a XOR a = 0`, `a XOR 0 = a`, self-inverse.
- **Fixed XOR:** XOR between two byte sequences of the same length.
- **One-time pad (OTP):** theoretically secure cipher based on XOR with a random single-use key.
- **`Vec<u8>`:** Rust type for mutable heap-allocated byte sequences.
- **Trait:** Rust polymorphism mechanism; `CryptoVec` adds cryptographic methods to `Vec<u8>`.
- **Error propagation:** `unwrap_or_else` pattern to convert errors to panics with a message.

## Code walkthrough

### Overview

The challenge uses `src/hex/mod.rs` to convert hex strings to bytes and `src/cryptovec/mod.rs` to perform the XOR operation. The `xor` method is defined in the `CryptoVec` trait implemented on `Vec<u8>`.

### Implementation

The `xor` method in the `CryptoVec` trait:

```rust
fn xor(&self, v2: Vec<u8>) -> Vec<u8> {
    self.iter().zip(v2.iter()).map(|(&x, &y)| x ^ y).collect()
}
```

`self.iter()` produces an iterator over the first vector. `.zip(v2.iter())` pairs elements of both iterators into tuples `(x, y)`. `.map(|(&x, &y)| x ^ y)` applies XOR to each byte pair — the `&x` and `&y` patterns dereference the references returned by the iterators. `.collect()` materializes the iterator into a new `Vec<u8>`. The method consumes `v2` by value (ownership) and takes `self` by reference: this signature choice reflects the operation's semantics (the second operand is consumed, the first is read).

Hex-to-bytes conversion uses `Hex::from_string` followed by `to_bytes()`, both already described in challenge 1.

Bytes-to-hex conversion uses `Hex::from_bytes`:

```rust
pub fn from_bytes(s: Vec<u8>) -> Result<Hex, JlmCryptoErrors> {
    let hex_string = s
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();
    Ok(Hex(hex_string))
}
```

`format!("{:02x}", byte)` formats each byte as two lowercase hex digits with zero-padding (`02` = minimum 2 digits, `x` = lowercase hex). The results are concatenated into a `String` via `collect::<String>()`.

### The test

```rust
#[test]
fn challenge_2() {
    let hex1 = Hex::from_string(String::from("1c0111001f010100061a024b53535009181c")).unwrap();
    let hex2 = Hex::from_string(String::from("686974207468652062756c6c277320657965")).unwrap();

    let bytes1 = hex1.to_bytes().unwrap_or_else(|err| {
        panic!("Error converting from Hex to byte: {:?}", err);
    });
    let bytes2 = hex2.to_bytes().unwrap_or_else(|err| {
        panic!("Error converting from Hex to byte: {:?}", err);
    });

    let xor_result = bytes1.xor(bytes2);

    let expected_result =
        Hex::from_string(String::from("746865206b696420646f6e277420706c6179")).unwrap();

    let result = Hex::from_bytes(xor_result).unwrap();
    assert_eq!(result, expected_result);
}
```

The test creates two `Hex` values, converts them to bytes with error handling via `unwrap_or_else`, performs XOR, converts the result to `Hex`, and compares to the expected value. The string `746865206b696420646f6e277420706c6179` is the hex ASCII encoding of "the kid don't play".

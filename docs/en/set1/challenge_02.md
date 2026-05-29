---
layout: default
title: "Challenge 2 — Fixed XOR"
parent: "Set 1 EN"
grand_parent: EN
nav_order: 2
permalink: /en/set1/challenge_02/
lang: en
---

# Challenge 2 — Fixed XOR

[← Previous](../challenge_01/) · [Next →](../challenge_03/) · [🇮🇹 Italiano](../../../it/set1/challenge_02/) · [Set 1](../) · [Home](../../)

---

## Theory

The XOR (exclusive-OR) operation is the fundamental building block of almost every modern cryptographic primitive. XOR operates bit-by-bit on two values: it returns 1 when the two bits differ, 0 when they are equal. Its algebraic properties make it ideal for cryptography: it is its own inverse (`A XOR B XOR B = A`), commutative (`A XOR B = B XOR A`), and associative.

Fixed-width XOR consists of applying XOR byte-by-byte between two arrays of equal length. This is the simplest case: no key reuse, no padding. It is used inside CBC mode (XOR between the previous ciphertext block and the plaintext block), in the One-Time Pad (when the key is as long as the message and used only once), and as a primitive in stream ciphers.

The One-Time Pad, based on fixed-width XOR with a random key never reused, is the only cipher with provable perfect secrecy. In practice, the difficulty of distributing keys as long as the message makes it impractical; however, the mathematical properties of XOR permeate every real-world cryptographic system.

Understanding XOR is also essential for cryptanalysis: if you know the plaintext and the corresponding XOR ciphertext, you can immediately recover the key (`key = ciphertext XOR plaintext`). This principle is called a "known-plaintext attack" and is the basis for challenges 3 and beyond.

## Key concepts

- **Bitwise XOR**: logical operation that produces 1 only when the input bits differ.
- **XOR self-inverse property**: `A XOR A = 0` and `A XOR 0 = A`, fundamental for encryption and decryption.
- **Fixed-width XOR**: XOR applied between two vectors of equal length, byte by byte.
- **One-Time Pad**: cipher with perfect secrecy based on XOR with a random single-use key.
- **Known-plaintext attack**: attack in which knowing the (key, ciphertext) pair allows recovering the text or vice versa.
- **`CryptoVec` trait**: Rust trait defined on `Vec<u8>` that collects all cryptographic operations on byte vectors.

## Code walkthrough

### Overview

The challenge uses `src/hex/mod.rs` for parsing hex strings and `src/cryptovec/mod.rs` for the XOR operation. The `xor` method is defined in the `CryptoVec` trait implemented on `Vec<u8>`.

### Implementation

After creating the two `Hex` objects via `from_string`, the test calls `to_bytes()` on both to obtain raw byte vectors:

```rust
let bytes1 = hex1.to_bytes().unwrap_or_else(|err| {
    panic!("Error converting from Hex to byte: {:?}", err);
});
let bytes2 = hex2.to_bytes().unwrap_or_else(|err| {
    panic!("Error converting from Hex to byte: {:?}", err);
});
```

The XOR operation is implemented in the `xor` method of the `CryptoVec` trait:

```rust
fn xor(&self, v2: Vec<u8>) -> Vec<u8> {
    self.iter().zip(v2.iter()).map(|(&x, &y)| x ^ y).collect()
}
```

The method uses `.zip()` to pair corresponding elements of the two iterators and `.map()` to apply the XOR operator `^` on each pair. The result is collected into a new `Vec<u8>`. Since `.zip()` stops at the shorter vector, both inputs must have the same length for a correct XOR.

Finally, the result is repackaged into a `Hex` object using `Hex::from_bytes`:

```rust
pub fn from_bytes(s: Vec<u8>) -> Result<Hex, JlmCryptoErrors> {
    let hex_string = s
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();
    Ok(Hex(hex_string))
}
```

The `{:02x}` format produces exactly two lowercase hex characters per byte, with leading zero if necessary.

### The test

```rust
#[test]
fn challenge_2() {
    let hex1 = Hex::from_string(String::from("1c0111001f010100061a024b53535009181c")).unwrap();
    let hex2 = Hex::from_string(String::from("686974207468652062756c6c277320657965")).unwrap();
    let bytes1 = hex1.to_bytes().unwrap_or_else(|err| panic!("{:?}", err));
    let bytes2 = hex2.to_bytes().unwrap_or_else(|err| panic!("{:?}", err));
    let xor_result = bytes1.xor(bytes2);
    let expected_result = Hex::from_string(String::from("746865206b696420646f6e277420706c6179")).unwrap();
    let result = Hex::from_bytes(xor_result).unwrap();
    assert_eq!(result, expected_result);
}
```

The test applies XOR to two equal-length byte arrays and verifies the result matches the expected hex value. The original values are masked ASCII text: "hit the bull's eye" XOR-ed with the other produces "the kid don't play".

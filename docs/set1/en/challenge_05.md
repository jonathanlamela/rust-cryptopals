---
layout: default
title: "Challenge 5 — Implement repeating-key XOR"
parent: "Set 1 — EN"
nav_order: 5
permalink: /set1/en/challenge_05/
lang: en
---

# Challenge 5 — Implement repeating-key XOR

[← Previous](../challenge_04/) · [Next →](../challenge_06/) · [🇮🇹 Italiano](../../it/challenge_05/) · [Set 1 index](../)

---

## Theory

The repeating-key XOR cipher, also known as the Vigenère cipher in the byte domain, is an extension of the single-byte XOR cipher. Instead of a single key byte, a fixed-length byte sequence is used that is repeated cyclically to cover the entire plaintext. Each plaintext byte is XORed with the corresponding byte of the cyclic key.

Historically, the Vigenère cipher (in its textual form) was considered unbreakable for centuries — it was called "le chiffre indéchiffrable". Its breaking by Charles Babbage and Friedrich Kasiski in the nineteenth century was a landmark achievement in cryptanalysis. The attack exploits the fact that identical plaintext blocks that align with the same key portion produce identical ciphertext blocks, revealing the key length and allowing the problem to be decomposed into a series of monoalphabetic ciphers.

In the byte domain, the same principle applies: if the key is "ICE" (3 bytes), byte i of the plaintext is XORed with `key[i % 3]`. The cyclic repetition creates statistical patterns that can be exploited by frequency analysis, as shown in challenge 6.

In Rust, the `cycle()` pattern on an iterator allows creation of an infinite iterator that repeats the original sequence. This is an idiomatic and safe approach compared to manual index arithmetic with modulo, which could lead to off-by-one bugs.

## Key concepts

- **Vigenère cipher (bytes):** XOR of each byte with the corresponding cyclic key byte.
- **Cyclic key:** the N-byte key is repeated to cover the entire message.
- **`cycle()`:** Rust iterator that infinitely repeats the underlying sequence.
- **Polyalphabetic cipher:** uses multiple alphabets cyclically (one per key position).
- **Statistical vulnerability:** ciphertext patterns reveal the key length.
- **`zip` on iterators:** pairs two iterators for element-wise operations.

## Code walkthrough

### Overview

The challenge uses the `repeating_key_xor` method of the `CryptoVec` trait in `src/cryptovec/mod.rs`. The test in `src/set1.rs` encrypts a known plaintext with a known key and compares the result to the expected ciphertext in hex format.

### Implementation

The `repeating_key_xor` method:

```rust
fn repeating_key_xor(&self, key: &[u8]) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    let mut key_iterator = key.into_iter().cycle();
    for i in self.into_iter() {
        result.push(key_iterator.next().unwrap() ^ i);
    }
    result
}
```

`key.into_iter().cycle()` creates an infinite iterator that scrolls through key bytes cyclically: when it reaches the end of the key it restarts from the beginning. `key_iterator.next().unwrap()` retrieves the next key byte — the `unwrap` is safe because `cycle()` produces an infinite iterator, so `next()` never returns `None`. For each plaintext byte `i`, XOR is performed with the current cyclic key byte.

The `&[u8]` signature for `key` accepts both arrays and byte slices (`b"ICE"` is a `&[u8; 3]` that can be coerced to `&[u8]`).

### The test

```rust
#[test]
fn challenge_5() {
    let expected_result = Hex::from_string(String::from(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    )).unwrap();
    let clear_text_as_bytes =
        b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".to_vec();
    let clear_key_as_bytes = b"ICE";

    let result = clear_text_as_bytes.repeating_key_xor(clear_key_as_bytes);
    let hex_result =
        Hex::from_bytes(result).unwrap_or_else(|_| panic!("Hex from bytes failed"));
    assert_eq!(expected_result, hex_result);
}
```

`b"..."` is a byte literal in Rust: it produces `&[u8]` or `&[u8; N]`. `.to_vec()` creates a `Vec<u8>` from the array. `b"ICE"` is the 3-byte key. The result is converted to hex and compared with the expected value.

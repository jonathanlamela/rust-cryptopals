---
layout: default
title: "Challenge 5 — Implement repeating-key XOR"
parent: "Set 1 EN"
grand_parent: EN
nav_order: 5
permalink: /en/set1/challenge_05/
lang: en
---

# Challenge 5 — Implement repeating-key XOR

[← Previous](../challenge_04/) · [Next →](../challenge_06/) · [🇮🇹 Italiano](../../../it/set1/challenge_05/) · [Set 1](../) · [Home](../../)

---

## Theory

The Vigenère cipher, invented in the 16th century, is the ancestor of repeating-key XOR ciphers. The idea is simple: a fixed-length key, much shorter than the message, is repeated cyclically to cover the entire text. Every byte of the message is combined with XOR with the corresponding byte of the repeated key.

Compared to the single-byte XOR cipher, this approach offers apparently greater security: instead of 256 possible keys, an exponentially larger key space must be confronted. However, the cipher is still vulnerable because every position in the key is used to encrypt a regular subset of the message characters. If the key is K bytes long, bytes at positions 0, K, 2K, ... are all encrypted with the same key byte; bytes at positions 1, K+1, 2K+1, ... with a second byte; and so on. Each sub-series is therefore a simple single-byte XOR cipher, attackable with frequency analysis.

This cipher is historically significant because it was used during the American Civil War (with the traditional Vigenère alphabet instead of XOR) and during the First and Second World Wars in more elaborate forms. Its structural weakness — the periodicity of the key — was formalized by the Kasiski method in 1863 and Friedman's index of coincidence in 1920.

Challenge 5 implements the encryption side; challenge 6 implements the decryption (the attack). Together they demonstrate the complete attack cycle: build the vulnerable primitive, then break it.

## Key concepts

- **Vigenère cipher**: polyalphabetic cipher using a repeated key to encrypt the message.
- **Cyclic key**: key repeated to cover the entire length of the message.
- **Periodicity**: property of the repeated key that makes the cipher vulnerable to column-wise frequency analysis.
- **`repeating_key_xor`**: `CryptoVec` method implementing repeating-key XOR encryption.
- **Cyclic iterator**: in Rust, the `.cycle()` method on an iterator creates an infinite sequence repeating the original.
- **Computational security**: the strength of a cipher depends not only on key length but also on algorithm structure.

## Code walkthrough

### Overview

The challenge uses `src/cryptovec/mod.rs`, specifically the `repeating_key_xor` method of the `CryptoVec` trait. The test verifies that the produced ciphertext matches the expected value.

### Implementation

The `repeating_key_xor` method is elegant in its simplicity:

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

The key point is the use of `.cycle()` on the key iterator. `cycle()` transforms a finite iterator into an infinite one that restarts from the beginning every time it reaches the end. This way, `key_iterator.next()` always returns a value, even when the message is much longer than the key. For each message byte (`i` in the iteration), XOR is performed with the next byte of the cyclic key. The result accumulates in a vector.

Note that the method takes `key: &[u8]` — a byte slice — rather than a generic type. This allows passing both byte literals (`b"ICE"`) and vectors (`&key_vec[..]`) without additional allocations.

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
    let hex_result = Hex::from_bytes(result).unwrap_or_else(|_| panic!("Hex from bytes failed"));
    assert_eq!(expected_result, hex_result);
}
```

The test encrypts an ASCII text with the key "ICE" and compares the result (converted to hex) with the expected value. The text is a fragment from "Play That Funky Music" by Vanilla Ice.

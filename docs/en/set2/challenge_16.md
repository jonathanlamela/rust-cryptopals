---
layout: default
title: "Challenge 16 — CBC bitflipping attacks"
parent: "Set 2 EN"
grand_parent: EN
nav_order: 8
permalink: /en/set2/challenge_16/
lang: en
---

# Challenge 16 — CBC bitflipping attacks

[← Previous](../challenge_15/) · [🇮🇹 Italiano](../../../it/set2/challenge_16/) · [Set 2](../) · [Home](../../)

---

## Theory

The CBC bitflipping attack exploits the mathematical property of CBC decryption: `P[i] = D(C[i]) XOR C[i-1]`. If an attacker modifies a bit in ciphertext block `C[i-1]`, the corresponding bit in decrypted plaintext `P[i]` will be flipped (XOR with 1). Block `P[i-1]` will be completely corrupted (since `D(C[i-1])` produces random-looking values), but block `P[i]` undergoes precise and controllable modifications.

An attacker can therefore: provide a known plaintext, encrypt it with CBC, modify bits in the ciphertext block preceding the target block, and obtain a decrypted text with the desired value in the target block. This is a "malleability" attack: even without knowing the key, a ciphertext can be produced that decrypts to a partially controlled value.

In this challenge, the oracle prepends and appends fixed strings to the plaintext, and quotes (escapes) the `=` and `;` characters. The attack consists of: providing the text `\x00admin\x00true` (where `\x00` will be transformed into `;` and `=` via bitflipping), encrypting, then modifying the correct bytes in the preceding block to turn the `\x00` bytes into `;` and `=`.

The calculation is: if we want the decrypted byte in block `i` to be `target`, and the current decrypted byte is `current`, we must XOR the corresponding byte of ciphertext block `i-1` with `current XOR target`. For `\x00 → ;`: XOR with `0 XOR 59 = 59`. For `\x00 → =`: XOR with `0 XOR 61 = 61`.

## Key concepts

- **Bitflipping attack**: attack that modifies specific bits of the CBC ciphertext to alter the decrypted text in a controlled way.
- **Malleability**: property of a cryptographic system where ciphertexts can be modified to produce modified decryptions.
- **`CustomCrypter16`**: struct managing string preparation with quoting of special characters.
- **`prepare_string`**: method adding prefix, quoted input, and suffix.
- **`quote_str` / `unquote_str`**: methods managing escape and unescape of `;` and `=` characters.
- **Error propagation**: the block preceding the target will be corrupted, but the target itself will be intact and modified as desired.

## Code walkthrough

### Overview

The challenge uses `src/crypters/custom_crypter_16.rs` for text preparation and `src/cryptovec/mod.rs` for CBC encryption and decryption.

### Implementation

`CustomCrypter16::prepare_string` builds the plaintext:

```rust
pub fn prepare_string(&self, input: &str) -> Vec<u8> {
    let input_quoted: String = self.quote_str(input);
    let input_bytes = input_quoted.as_bytes();
    let prepend_bytes = b"comment1=cooking%20MCs;userdata=";
    let append_bytes = b";comment2=%20like%20a%20pound%20of%20bacon";
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(&prepend_bytes[..]);
    plaintext.extend_from_slice(&input_bytes[..]);
    plaintext.extend_from_slice(&append_bytes[..]);
    plaintext
}
```

The prefix `"comment1=cooking%20MCs;userdata="` is exactly 32 bytes (2 blocks). So user text starts in the third block. The input `"\x00admin\x00true"` is in the third block, and to modify it we must alter the second block (bytes 16 and 22 of the ciphertext).

In the test, bytes 16 and 22 of the ciphertext are XOR-ed to produce `;` and `=`:

```rust
encrypted2[16] ^= 59; // ASCII of ';'
encrypted2[22] ^= 61; // ASCII of '='
```

After decryption and unquoting, the string will contain `;admin=true;`.

### The test

```rust
#[test]
pub fn challenge_16() {
    let key_size: usize = 16;
    let iv: Vec<u8> = key_size.random_block();
    let key = key_size.random_block();
    let oracle = CustomCrypter16::new();
    // Part 1: direct encryption with ;admin=true; in string
    let plaintext1 = oracle.prepare_string("testing 123;admin=true;blah");
    let encrypted1 = plaintext1.ssl_cbc_encrypt(&key, &iv, Some(true)).unwrap();
    let decrypted1 = encrypted1.ssl_cbc_decrypt(&key, &iv, Some(true)).unwrap();
    let unquoted1 = oracle.unquote_str(&String::from_utf8_lossy(&decrypted1));
    assert_eq!(unquoted1.find(";admin=true;").is_some(), true);
    // Part 2: bitflipping
    let plaintext2 = oracle.prepare_string("\x00admin\x00true");
    let mut encrypted2 = plaintext2.ssl_cbc_encrypt(&key, &iv, Some(true)).unwrap();
    encrypted2[16] ^= 59;
    encrypted2[22] ^= 61;
    let decrypted2 = encrypted2.ssl_cbc_decrypt(&key, &iv, Some(true)).unwrap();
    let unquoted2 = oracle.unquote_str(&String::from_utf8_lossy(&decrypted2));
    assert_eq!(unquoted2.find(";admin=true;").is_some(), true);
}
```

Part 1 verifies quoting works: `;` and `=` characters are quoted then unquoted, producing the original string with `;admin=true;`. Part 2 performs the real attack using bitflipping.

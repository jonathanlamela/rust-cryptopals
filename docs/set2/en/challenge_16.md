---
layout: default
title: "Challenge 16 — CBC bitflipping attacks"
parent: "Set 2 — EN"
nav_order: 8
permalink: /set2/en/challenge_16/
lang: en
---

# Challenge 16 — CBC bitflipping attacks

[← Previous](../challenge_15/) · [🇮🇹 Italiano](../../it/challenge_16/) · [Set 2 index](../)

---

## Theory

The CBC bitflipping attack exploits the structure of CBC decryption: the plaintext of a block is the result of decrypting the current ciphertext block XORed with the previous ciphertext block. Modifying one byte of ciphertext block C[i] predictably modifies the corresponding byte of plaintext P[i+1], at the cost of completely corrupting P[i].

The precise mechanics are: `P[i+1][j] = Decrypt(C[i+1])[j] XOR C[i][j]`. If we want `P[i+1][j]` to take a target value `t`, and it currently has value `v`, simply modify `C[i][j]` with `C[i][j] XOR v XOR t`. This is deterministic and does not require knowledge of the key.

In the challenge scenario, the oracle prepends and appends data to the plaintext and encrypts it with CBC. The input is "quoted" (`;` and `=` characters are escaped). The goal is to produce a ciphertext that, when decrypted and unquoted, contains `;admin=true;`. Since `;` is ASCII 59 (0x3b) and `=` is ASCII 61 (0x3d), the bytes `\x00` can be used in their place in the input (which are not quoted), then the ciphertext is modified to convert them to the target values.

This attack demonstrates that CBC does not provide message integrity: an attacker who can modify the ciphertext can alter the plaintext in a controlled manner. The correct solution is to use authenticated encryption (e.g., AES-GCM or ChaCha20-Poly1305).

## Key concepts

- **CBC bitflipping:** predictable plaintext modification by altering the previous block's ciphertext.
- **`prepare_string`:** adds prefix/suffix and quotes `;` and `=` characters.
- **`unquote_str`:** removes quotes introduced by `quote_str`.
- **`CustomCrypter16`:** oracle for string preparation and verification.
- **Controlled XOR:** `C[i][j] ^= target_char XOR current_char` to obtain the desired character.
- **Previous block corruption:** block P[i] becomes garbage, but P[i+1] is what matters.

## Code walkthrough

### Overview

`src/crypters/custom_crypter_16.rs` defines `CustomCrypter16` with methods `prepare_string`, `quote_str`, and `unquote_str`. The test in `src/set2.rs` performs both quoting verification (part 1) and the bitflipping attack (part 2).

### Implementation

`quote_str` replaces `;` with `";"` and `=` with `"="`. `unquote_str` reverses this. `prepare_string` prepends `comment1=cooking%20MCs;userdata=` (32 bytes = 2 exact blocks) and appends `;comment2=%20like%20a%20pound%20of%20bacon`, so the user input starts at block 2.

### The test

```rust
#[test]
pub fn challenge_16() {
    let key_size: usize = 16;
    let iv: Vec<u8> = key_size.random_block();
    let key = key_size.random_block();
    let oracle = CustomCrypter16::new();

    // Part 1: quoting works
    let plaintext1 = oracle.prepare_string("testing 123;admin=true;blah");
    let encrypted1 = plaintext1.ssl_cbc_encrypt(&key, &iv, Some(true)).unwrap();
    let decrypted1 = encrypted1.ssl_cbc_decrypt(&key, &iv, Some(true)).unwrap();
    let decrypted_string1 = String::from_utf8_lossy(&decrypted1);
    let unquoted1 = oracle.unquote_str(&decrypted_string1);
    assert_eq!(unquoted1.find(";admin=true;").is_some(), true);

    // Part 2: bitflipping
    let plaintext2 = oracle.prepare_string("\x00admin\x00true");
    let mut encrypted2 = plaintext2.ssl_cbc_encrypt(&key, &iv, Some(true)).unwrap();
    encrypted2[16] ^= 59;  // \x00 → ;  (59 = ASCII ';')
    encrypted2[22] ^= 61;  // \x00 → =  (61 = ASCII '=')
    let decrypted2 = encrypted2.ssl_cbc_decrypt(&key, &iv, Some(true)).unwrap();
    let decrypted_string2 = String::from_utf8_lossy(&decrypted2);
    let unquoted2 = oracle.unquote_str(&decrypted_string2);
    assert_eq!(unquoted2.find(";admin=true;").is_some(), true);
}
```

`encrypted2[16]` is the first byte of the second ciphertext block. XORing it with 59 changes the corresponding byte in the third plaintext block (which contains our input `\x00admin\x00true`) from `\x00` to `;`. Similarly for `encrypted2[22]` → `=`.

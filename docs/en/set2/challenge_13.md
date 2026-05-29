---
layout: default
title: "Challenge 13 — ECB cut-and-paste"
parent: "Set 2 EN"
grand_parent: EN
nav_order: 5
permalink: /en/set2/challenge_13/
lang: en
---

# Challenge 13 — ECB cut-and-paste

[← Previous](../challenge_12/) · [Next →](../challenge_14/) · [🇮🇹 Italiano](../../../it/set2/challenge_13/) · [Set 2](../) · [Home](../../)

---

## Theory

The ECB cut-and-paste attack exploits ECB's property that each block is encrypted and decrypted independently. If we can get the oracle to encrypt a block containing exactly the desired value (e.g., "admin"), we can "cut" that block from the ciphertext and "paste" it into another ciphertext to produce a tampered message.

In this challenge, the oracle creates user profiles in the format `email=...&uid=10&role=user`, encrypted in ECB. The goal is to produce a profile with `role=admin`. To do so, we follow these steps:

1. Create an email whose value, after `email=`, positions the next block at the start of a new block. With `email=` (6 bytes) plus 10 bytes of junk = 16 bytes (one complete block). The second block starts with our controlled text.
2. Use as email `AAAAAAAAAAadmin\x0b\x0b...\x0b` (10 junk bytes + "admin" + 11 bytes of padding 0x0b). The second ciphertext block will contain `encrypt("admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b")`.
3. Create a second profile with a normal email (e.g., 9 characters) such that `email=...&uid=10&role=` is exactly 32 bytes (2 blocks), and the third block begins with "user".
4. Replace the third block of the second ciphertext with the second block of the first ciphertext.
5. The decrypted result will be `email=...&uid=10&role=admin`.

## Key concepts

- **ECB cut-and-paste**: attack that reassembles ciphertext blocks from different sessions to forge a malformed message.
- **Block boundary**: precise alignment of input to make a target value start at the beginning of a block.
- **`CustomCrypter13`**: oracle creating cookie profiles in the format `email=...&uid=10&role=user`.
- **`profile_for`**: method building the profile string, rejecting inputs containing `&` or `=`.
- **`generate_test_email`**: method generating a 9-character email for block alignment.
- **Manual padding**: addition of 11 bytes of value 0x0b to complete the "admin" block.

## Code walkthrough

### Overview

The challenge uses `src/crypters/custom_crypter_13.rs` for the cookie oracle and `src/cryptovec/mod.rs` for ECB encryption.

### Implementation

`CustomCrypter13` uses an `OracleBase` with prefix `b"email="` and suffix `b"&uid=10&role=user"`. Its `Oracle` trait implementation directly encrypts the byte slice with ECB:

```rust
fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>, JlmCryptoErrors> {
    Ok(u.to_vec().ssl_ecb_encrypt(&self.base.key, Some(true)).unwrap())
}
```

`profile_for` constructs the profile string while blocking injection characters:

```rust
pub fn profile_for(&self, email: String) -> Result<String, JlmCryptoErrors> {
    if email.contains("&") {
        return Err(JlmCryptoErrors::InvalidSet2Challenge13Chars);
    } else {
        let mut result_string = String::from("email=");
        result_string.push_str(&email);
        result_string.push_str("&uid=10&role=user");
        Ok(result_string)
    }
}
```

### The test

The test crafts an admin profile by extracting the ciphertext block containing "admin" and pasting it as the third block of a normal profile:

```rust
ciphertext2.truncate(32);
ciphertext2.extend_from_slice(&last_block);
let new_cookie_decrypted = ciphertext2.to_vec()
    .ssl_ecb_decrypt(&oracle13.base.key, Some(true)).unwrap();
assert!(String::from_utf8(new_cookie_decrypted).unwrap().ends_with("role=admin"));
```

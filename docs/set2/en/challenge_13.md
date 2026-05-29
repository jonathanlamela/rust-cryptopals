---
layout: default
title: "Challenge 13 — ECB cut-and-paste"
parent: "Set 2 — EN"
nav_order: 5
permalink: /set2/en/challenge_13/
lang: en
---

# Challenge 13 — ECB cut-and-paste

[← Previous](../challenge_12/) · [Next →](../challenge_14/) · [🇮🇹 Italiano](../../it/challenge_13/) · [Set 2 index](../../)

---

## Theory

The ECB cut-and-paste attack exploits ECB's lack of integrity: since each block is independent, an attacker can rearrange encrypted blocks to produce a different plaintext when decrypted. Knowledge of the key is not required.

The scenario is an authentication system that encrypts user profiles in ECB and uses them as cookies. A profile has the form `email=xxx&uid=10&role=user`. The system sanitizes `&` and `=` characters from the email, but does not prevent the cut-and-paste attack.

The strategy has two phases. First, create a ciphertext where the second block (bytes 16–31) contains the encryption of `admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b` (the word "admin" with PKCS#7 padding to reach 16 bytes). Then create a second ciphertext with a crafted email that causes `email=xxx&uid=10&role=` to end exactly at a block boundary. Replacing the last block of this second ciphertext with the "admin" block extracted from the first causes the decrypted plaintext to end with `role=admin` instead of `role=user`.

This attack demonstrates that confidentiality without integrity is insufficient. A secure system must use a MAC (Message Authentication Code) or authenticated encryption (AEAD) to ensure the ciphertext cannot be modified.

## Key concepts

- **ECB cut-and-paste:** rearranging ECB blocks to obtain a different plaintext.
- **Lack of integrity:** ECB has no mechanism to detect ciphertext modifications.
- **Boundary alignment:** the email is chosen to align `role=` at the end of a block.
- **`profile_for`:** builds the profile string from the email (with sanitisation).
- **`generate_test_email`:** generates an email of the right length for the attack.
- **PKCS#7 padding as data:** inserts padding as part of the controlled plaintext.

## Code walkthrough

### Overview

`src/crypters/custom_crypter_13.rs` defines `CustomCrypter13` with ECB encryption and profile construction methods. The test in `src/set2.rs` performs the attack manually.

### Implementation

`CustomCrypter13::new` sets up a fixed prefix `email=` and suffix `&uid=10&role=user`. `profile_for` sanitises the input and builds the profile string, rejecting any email containing `&`.

### The test

```rust
#[test]
pub fn challenge_13() {
    let oracle13 = CustomCrypter13::new().unwrap();
    let email = &String::from(oracle13.generate_test_email());
    let junk1: Vec<u8> = vec![65u8; 10];
    let mut admin_with_padding = b"admin".to_vec();
    let padding = vec![11; 11];
    admin_with_padding.extend_from_slice(&padding[..]);
    let mut test_bytes = Vec::new();
    test_bytes.extend_from_slice(&junk1[..]);
    test_bytes.extend_from_slice(&admin_with_padding[..]);
    let ciphertext1 = &oracle13.encrypt(
        &oracle13.profile_for(String::from_utf8(test_bytes[..].to_vec()).unwrap()).unwrap().as_bytes(),
    ).unwrap();
    let mut ciphertext1_chunks = ciphertext1.chunks(16);
    let ciphertext2 = &mut oracle13.encrypt(
        &oracle13.profile_for(email.to_string()).unwrap().as_bytes()
    ).unwrap();
    let last_block = ciphertext1_chunks.nth(1).unwrap();
    ciphertext2.truncate(32);
    ciphertext2.extend_from_slice(&last_block);
    let new_cookie_decrypted = ciphertext2.to_vec()
        .ssl_ecb_decrypt(&oracle13.base.key, Some(true)).unwrap();
    assert!(String::from_utf8(new_cookie_decrypted).unwrap().ends_with("role=admin"));
}
```

The attack in detail: 10 'A' bytes of `junk1` align `admin\x0b...\x0b` to the second block (bytes 16–31). `generate_test_email` produces a 9-character email (`xxxx@yyyy.com`) that brings `email=xxxx@yyyy.com&uid=10&role=` to exactly 32 bytes (2 blocks). The third block of `ciphertext2` is replaced with the second block of `ciphertext1`, producing a profile that decrypts with `role=admin`.

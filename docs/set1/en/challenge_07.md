---
layout: default
title: "Challenge 7 — AES in ECB mode"
parent: "Set 1 — EN"
nav_order: 7
permalink: /set1/en/challenge_07/
lang: en
---

# Challenge 7 — AES in ECB mode

[← Previous](../challenge_06/) · [Next →](../challenge_08/) · [🇮🇹 Italiano](../../it/challenge_07/) · [Set 1 index](../../)

---

## Theory

The Advanced Encryption Standard (AES) is the most widely used block cipher in the world, standardized by NIST in 2001. It is a symmetric block cipher: it uses the same key to encrypt and decrypt, and operates on 128-bit (16-byte) blocks. Supported key lengths are 128, 192, and 256 bits.

ECB (Electronic CodeBook) mode is the simplest block cipher operating mode: each 16-byte plaintext block is encrypted independently with the same key. This simplicity is also its greatest weakness: identical plaintext blocks produce identical ciphertext blocks, making patterns in the original message visible. This problem is dramatically illustrated by the "ECB Penguin" image — a bitmap image of a penguin encrypted in ECB mode still clearly shows the penguin's outline.

In this challenge, the task is to decrypt a Base64 ciphertext with a known key ("YELLOW SUBMARINE") in AES-ECB mode. This demonstrates correct implementation before moving on to the attacks in subsequent sets.

The implementation uses OpenSSL via the `openssl` crate, which exposes the Rust API for OpenSSL cryptographic operations. Using verified libraries is correct production practice; implementing AES from scratch is an academic exercise that introduces side-channel and implementation risks.

PKCS#7 padding, introduced in challenge 9, is applied automatically by OpenSSL in ECB mode when `pad` is `true`.

## Key concepts

- **AES (Advanced Encryption Standard):** symmetric block cipher with 128/192/256-bit key, 128-bit block.
- **ECB mode:** each block encrypted independently with the same key; vulnerable to patterns.
- **OpenSSL `Crypter`:** Rust API for symmetric operations (encrypt/decrypt, ECB/CBC/CTR).
- **`Cipher::aes_128_ecb()`:** selects AES-128 in ECB mode.
- **`Mode::Decrypt`:** decryption mode.
- **Automatic PKCS#7 padding:** OpenSSL handles padding/unpadding when `pad(true)`.

## Code walkthrough

### Overview

The `ssl_ecb_decrypt` method is defined in the `CryptoVec` trait in `src/cryptovec/mod.rs`. It uses the `openssl` crate to invoke AES-128-ECB. The test in `src/set1.rs` loads the ciphertext from Base64, decrypts it, and verifies the plaintext.

### Implementation

The `ssl_ecb_decrypt` method:

```rust
fn ssl_ecb_decrypt(&self, key: &[u8], pad: Option<bool>) -> Result<Vec<u8>, JlmCryptoErrors> {
    let cipher = Cipher::aes_128_ecb();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, None).unwrap();
    crypter.pad(pad.unwrap_or(true));
    let mut decrypted = vec![0; &self.len() + cipher.block_size()];
    let count = crypter.update(&self, &mut decrypted).unwrap();
    match crypter.finalize(&mut decrypted[count..]) {
        Ok(final_count_value) => {
            decrypted.truncate(count + final_count_value);
            Ok(decrypted)
        }
        Err(_) => Err(JlmCryptoErrors::InvalidPadding),
    }
}
```

`Cipher::aes_128_ecb()` selects the algorithm. `Crypter::new` creates an encryption context; the fourth parameter is the IV (not used in ECB, hence `None`). `crypter.pad(true)` enables automatic padding. `crypter.update` processes the ciphertext; the output buffer must have space for the current block plus one extra block (`self.len() + cipher.block_size()`). `crypter.finalize` completes decryption and removes PKCS#7 padding. `decrypted.truncate` removes unused bytes from the output buffer.

### The test

```rust
#[test]
fn challenge_7() {
    let expected_result = String::from("testo di prova");
    let encrypted_content = Base64::from_string(String::from("ZlBz+2/3RVo7TTsubWlesA=="));
    let encrypted_bytes = encrypted_content
        .to_bytes()
        .unwrap_or_else(|_| panic!("Base64 to bytes failed"));
    let decrypted_bytes = encrypted_bytes
        .ssl_ecb_decrypt(b"YELLOW SUBMARINE", Some(true))
        .unwrap();
    let decrypted_string = str::from_utf8(&decrypted_bytes).unwrap().to_string();
    assert_eq!(decrypted_string, expected_result)
}
```

The test uses a custom Base64 ciphertext (not the original Cryptopals file, which encrypted an entire song) and verifies that decryption produces "testo di prova". The key "YELLOW SUBMARINE" is the canonical key used throughout the Cryptopals challenges.

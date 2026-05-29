---
layout: default
title: "Challenge 7 — AES in ECB mode"
parent: "Set 1 EN"
grand_parent: EN
nav_order: 7
permalink: /en/set1/challenge_07/
lang: en
---

# Challenge 7 — AES in ECB mode

[← Previous](../challenge_06/) · [Next →](../challenge_08/) · [🇮🇹 Italiano](../../../it/set1/challenge_07/) · [Set 1](../) · [Home](../../)

---

## Theory

AES (Advanced Encryption Standard) is the de facto symmetric block cipher standard adopted by NIST in 2001 after a public competition. AES operates on 128-bit (16-byte) blocks with 128-, 192-, or 256-bit keys. The internal algorithm involves 10, 12, or 14 rounds of transformations (SubBytes, ShiftRows, MixColumns, AddRoundKey) that ensure confusion and diffusion.

ECB (Electronic CodeBook) mode is the simplest way to use a block cipher: each 16-byte block of plaintext is encrypted independently of the others using the same key. The simplicity is both its strength (easily parallelizable, bit errors do not propagate between blocks) and its main weakness: identical plaintext blocks produce identical ciphertext blocks. This means the structure of the plaintext is partially visible in the ciphertext: if an image is encrypted in ECB, its outlines and patterns can still be distinguished (the famous "ECB penguin").

For this reason, ECB should never be used in practice to encrypt more than one block of data. However, it is a fundamental building block for more secure modes: CBC uses ECB internally (with the addition of XOR with the previous block), and CTR uses ECB to generate the keystream.

In this challenge, AES-ECB is used to decrypt a real ciphertext using the key "YELLOW SUBMARINE". The implementation uses the OpenSSL library via the `openssl` crate.

## Key concepts

- **AES**: symmetric block cipher with 128-bit blocks, NIST standard since 2001.
- **ECB mode**: each block is encrypted independently; identical blocks produce identical ciphertexts.
- **PKCS#7 padding**: padding scheme that brings the plaintext to a multiple of the block length.
- **`ssl_ecb_decrypt`**: `CryptoVec` method using OpenSSL to decrypt with AES-128-ECB.
- **`openssl` crate**: Rust bindings to the OpenSSL cryptographic library, used for AES primitives.
- **Symmetric key**: the same key is used for both encryption and decryption.

## Code walkthrough

### Overview

The challenge uses `src/cryptovec/mod.rs`, specifically `ssl_ecb_decrypt`, which delegates to OpenSSL via the `openssl` crate. The test also uses `src/base64/mod.rs` to decode the ciphertext from Base64.

### Implementation

`ssl_ecb_decrypt` uses the OpenSSL APIs:

```rust
fn ssl_ecb_decrypt(
    &self,
    key: &[u8],
    pad: Option<bool>,
) -> Result<Vec<u8>, JlmCryptoErrors> {
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

The process has three phases: create the `Crypter` with mode, key, and IV (None for ECB); call `update` to process data; call `finalize` to handle final padding. The output buffer is allocated with `self.len() + cipher.block_size()` to provide sufficient space.

The `pad: Option<bool>` parameter controls whether OpenSSL should automatically strip PKCS#7 padding during decryption. With `Some(true)` (default), padding is removed. With `Some(false)`, the padding bytes remain in the result.

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

The test decrypts a Base64 string with the key "YELLOW SUBMARINE" and verifies the result is "testo di prova". Note that this implementation uses an Italian test string instead of the original Cryptopals content, preserving the structure of the exercise.

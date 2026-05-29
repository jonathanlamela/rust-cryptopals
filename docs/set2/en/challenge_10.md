---
layout: default
title: "Challenge 10 — Implement CBC mode"
parent: "Set 2 — EN"
nav_order: 2
permalink: /set2/en/challenge_10/
lang: en
---

# Challenge 10 — Implement CBC mode

[← Previous](../challenge_09/) · [Next →](../challenge_11/) · [🇮🇹 Italiano](../../it/challenge_10/) · [Set 2 index](../../)

---

## Theory

CBC (Cipher Block Chaining) mode was designed to solve ECB's main weakness: producing identical ciphertext blocks for identical plaintext blocks. In CBC, each plaintext block is XORed with the previous ciphertext block before being encrypted with the key. The first block uses a special value called the IV (Initialization Vector), which should be random and unique for each session.

This chain of dependencies creates the "diffusion" property: a single bit changed in the plaintext or ciphertext propagates through all subsequent blocks, making statistical analysis much harder. Unlike ECB, identical plaintext blocks produce different ciphertext blocks if preceded by different blocks.

For CBC decryption, the process is reversed: each ciphertext block is decrypted with the key, then XORed with the previous ciphertext block (or with the IV for the first block) to obtain the plaintext. This asymmetry between encryption and decryption has important implications for attacks: challenge 16 shows how modifying the ciphertext can predictably affect the decrypted plaintext.

The code implements both a manual "legacy" version (using `ssl_ecb_decrypt` for each block) and an OpenSSL version that automatically handles the entire CBC mode.

## Key concepts

- **CBC (Cipher Block Chaining):** XOR the plaintext with the previous ciphertext before encryption.
- **IV (Initialization Vector):** random value used for XOR of the first block; must be unique per message.
- **Diffusion:** a change in one block propagates to all subsequent blocks.
- **`legacy_cbc_decrypt`:** manual CBC implementation using ECB for each block.
- **`ssl_cbc_decrypt`/`ssl_cbc_encrypt`:** OpenSSL-based implementation.
- **Independent decryption:** each CBC block can be decrypted independently (unlike encryption).

## Code walkthrough

### Overview

`src/cryptovec/mod.rs` contains both `legacy_cbc_decrypt` (manual implementation) and `ssl_cbc_encrypt`/`ssl_cbc_decrypt` (OpenSSL implementation). The test uses OpenSSL to decrypt the data file.

### Implementation

The `legacy_cbc_decrypt` method shows CBC mechanics:

```rust
fn legacy_cbc_decrypt(&self, key: &[u8], iv: &mut [u8]) -> Result<Vec<u8>, JlmCryptoErrors> {
    let block_size = 16;
    let mut plaintext = Vec::new();
    let mut prev_ciphertext_block = iv.to_vec();
    for chunk in self.chunks(block_size) {
        let decrypted_block = chunk.to_vec().ssl_ecb_decrypt(key, Some(false)).unwrap();
        let mut decrypted_block_xor = Vec::with_capacity(block_size);
        for j in 0..block_size {
            decrypted_block_xor.push(decrypted_block[j] ^ prev_ciphertext_block[j]);
        }
        prev_ciphertext_block = chunk.to_vec();
        plaintext.extend_from_slice(&decrypted_block_xor);
    }
    let _ = plaintext.unpad(16);
    Ok(plaintext)
}
```

For each ciphertext block: (1) decrypt with AES-ECB without padding (`Some(false)`); (2) XOR with the previous ciphertext block (initially the IV); (3) update the "previous block" with the current ciphertext block; (4) append the decrypted plaintext to the result.

The `ssl_cbc_encrypt` method uses OpenSSL directly:

```rust
fn ssl_cbc_encrypt(&self, key: &[u8], iv: &[u8], pad: Option<bool>) -> Result<Vec<u8>, JlmCryptoErrors> {
    let cipher = Cipher::aes_128_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv)).unwrap();
    crypter.pad(pad.unwrap_or(true));
    let mut encrypted = vec![0; &self.len() + cipher.block_size()];
    let count = crypter.update(&self, &mut encrypted).unwrap();
    match crypter.finalize(&mut encrypted[count..]) {
        Ok(final_count_value) => {
            encrypted.truncate(count + final_count_value);
            Ok(encrypted)
        }
        Err(_) => Err(JlmCryptoErrors::InvalidPadding),
    }
}
```

The difference from ECB is `Cipher::aes_128_cbc()` and `Some(iv)` in the `Crypter` constructor.

### The test

```rust
#[test]
fn challenge_10() {
    let file_path = "./data/data_10.txt";
    let mut file = File::open(file_path).expect("Unable to read file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Error reading file.");
    let buffer_to_string = str::from_utf8(&buffer).unwrap().replace("\n", "");
    let input = Base64::from_string(buffer_to_string);
    let input_bytes = input.to_bytes().unwrap_or_else(|_| panic!("Invalid Base64 to bytes"));
    let iv = &[0; 16];
    if let Ok(v) = input_bytes.legacy_cbc_decrypt(b"YELLOW SUBMARINE", &mut iv.to_owned()) {
        let result = String::from_utf8(v).unwrap();
        assert_eq!(YELLOW_SUBMARINE_STRING, result)
    }
}
```

The file contains Base64 ciphertext encrypted with AES-CBC, key "YELLOW SUBMARINE" and all-zero IV. The test decrypts and verifies that the plaintext is "Play That Funky Music".

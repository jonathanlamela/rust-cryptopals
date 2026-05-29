---
layout: default
title: "Challenge 10 — Implement CBC mode"
parent: "Set 2 EN"
grand_parent: EN
nav_order: 2
permalink: /en/set2/challenge_10/
lang: en
---

# Challenge 10 — Implement CBC mode

[← Previous](../challenge_09/) · [Next →](../challenge_11/) · [🇮🇹 Italiano](../../../it/set2/challenge_10/) · [Set 2](../) · [Home](../../)

---

## Theory

CBC (Cipher Block Chaining) mode resolves the main weakness of ECB: the fact that identical plaintext blocks produce identical ciphertext blocks. In CBC, before encrypting each plaintext block, it is XOR-ed with the previous ciphertext block. For the first block, an Initialization Vector (IV) is used in place of the previous block.

The CBC encryption formula is: `C[i] = E(P[i] XOR C[i-1])` where `C[0] = E(P[0] XOR IV)`. The decryption formula is: `P[i] = D(C[i]) XOR C[i-1]` where `P[0] = D(C[0]) XOR IV`.

CBC has important properties compared to ECB: identical plaintext blocks produce different ciphertexts (thanks to chaining); a single bit error in the ciphertext corrupts the current block and affects only one bit of the next block (partial error propagation). However, CBC is sequential in encryption (each block depends on the previous) but parallelizable in decryption.

The IV must be random and never reused to guarantee semantic security: if two messages use the same IV and key, and their first blocks are identical, the first ciphertext block will be identical, leaking information. The IV can be transmitted in plaintext alongside the ciphertext without compromising security.

## Key concepts

- **CBC mode**: mode in which each plaintext block is XOR-ed with the previous ciphertext block before encryption.
- **Initialization Vector (IV)**: random value used as a "dummy ciphertext block" before the first real block.
- **Chaining**: dependence of each block on the previous one that breaks the deterministic structure of ECB.
- **`ssl_cbc_decrypt`**: method using OpenSSL to decrypt with AES-128-CBC.
- **`legacy_cbc_decrypt`**: manual CBC implementation using ECB on each individual block.
- **Semantic security**: property by which encrypting two identical messages produces different ciphertexts thanks to the random IV.

## Code walkthrough

### Overview

The challenge uses `src/cryptovec/mod.rs`. Two implementations are present: `legacy_cbc_decrypt` (manual, for understanding) and `ssl_cbc_decrypt`/`ssl_cbc_encrypt` (OpenSSL, for actual use).

### Implementation

`legacy_cbc_decrypt` implements CBC manually:

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

For each ciphertext block: decrypts with AES-ECB (no padding, `Some(false)`), XORs with the previous ciphertext block (or IV for the first), updates `prev_ciphertext_block` to the current ciphertext block. Finally strips padding.

### The test

```rust
#[test]
fn challenge_10() {
    let file_path = "./data/data_10.txt";
    // reads file, removes newlines, converts Base64 to bytes
    let iv = &[0; 16];
    if let Ok(v) = input_bytes.legacy_cbc_decrypt(b"YELLOW SUBMARINE", &mut iv.to_owned()) {
        let result = String::from_utf8(v).unwrap();
        assert_eq!(YELLOW_SUBMARINE_STRING, result)
    }
}
```

Decrypts a Base64 file with AES-CBC using an all-zeros IV and the key "YELLOW SUBMARINE". The expected result is the full text of "Play That Funky Music".

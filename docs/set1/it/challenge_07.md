---
layout: default
title: "Sfida 7 — Decifra AES in modalità ECB"
parent: "Set 1 — IT"
nav_order: 7
permalink: /set1/it/challenge_07/
lang: it
---

# Sfida 7 — Decifra AES in modalità ECB

[← Sfida precedente](../challenge_06/) · [Sfida successiva →](../challenge_08/) · [🇬🇧 English](../../en/challenge_07/) · [Indice Set 1](../)

---

## Teoria

L'Advanced Encryption Standard (AES) è il cifrario a blocchi più diffuso al mondo, standardizzato dal NIST nel 2001. È un cifrario a blocchi simmetrico: usa la stessa chiave per cifrare e decifrare, e opera su blocchi di 128 bit (16 byte). Le lunghezze di chiave supportate sono 128, 192 e 256 bit.

La modalità ECB (Electronic CodeBook) è la più semplice modalità operativa di un cifrario a blocchi: ogni blocco di 16 byte del plaintext viene cifrato indipendentemente con la stessa chiave. Questa semplicità è anche la sua maggiore debolezza: blocchi di plaintext identici producono blocchi di ciphertext identici, rendendo visibili i pattern nel messaggio originale. Questo problema è drammaticamente illustrato dall'immagine del "Pinguino ECB" — l'immagine bitmap di un pinguino cifrata in ECB mostra ancora chiaramente il contorno del pinguino.

In questa sfida, il compito è decifrare un ciphertext Base64 con una chiave nota ("YELLOW SUBMARINE") in modalità AES-ECB. Questo dimostra il funzionamento corretto dell'implementazione prima di passare agli attacchi dei set successivi.

L'implementazione usa OpenSSL tramite la crate `openssl`, che espone l'API Rust per le operazioni crittografiche della libreria OpenSSL. L'uso di librerie verificate è la pratica corretta in produzione; implementare AES da zero è un esercizio accademico che introduce rischi di side-channel e implementazione.

Il padding PKCS#7, già introdotto nella sfida 9, viene applicato automaticamente da OpenSSL nella modalità ECB quando `pad` è `true`.

## Concetti chiave

- **AES (Advanced Encryption Standard):** cifrario a blocchi simmetrico a 128/192/256 bit di chiave, blocco di 128 bit.
- **Modalità ECB:** ogni blocco cifrato indipendentemente con la stessa chiave; vulnerabile ai pattern.
- **`Crypter` di OpenSSL:** API Rust per operazioni simmetriche (encrypt/decrypt, ECB/CBC/CTR).
- **`Cipher::aes_128_ecb()`:** seleziona AES-128 in modalità ECB.
- **`Mode::Decrypt`:** modalità di decifratura.
- **Padding PKCS#7 automatico:** OpenSSL gestisce il padding/unpadding quando `pad(true)`.

## Spiegazione del codice

### Struttura generale

Il metodo `ssl_ecb_decrypt` è definito nel trait `CryptoVec` in `src/cryptovec/mod.rs`. Usa la crate `openssl` per invocare AES-128-ECB. Il test in `src/set1.rs` carica il ciphertext da Base64, lo decifra e verifica il plaintext.

### Implementazione

Il metodo `ssl_ecb_decrypt`:

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

`Cipher::aes_128_ecb()` seleziona l'algoritmo. `Crypter::new` crea un contesto di cifratura; il quarto parametro è l'IV (non usato in ECB, quindi `None`). `crypter.pad(true)` abilita il padding automatico. `crypter.update` processa il ciphertext; l'output buffer deve avere spazio per il blocco corrente più un blocco extra (`self.len() + cipher.block_size()`). `crypter.finalize` completa la decifratura e rimuove il padding PKCS#7. `decrypted.truncate` rimuove i byte non usati dall'output buffer.

### Il test

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

Il test usa un ciphertext Base64 personalizzato (non il file originale delle Cryptopals, che usava un'intera canzone) e verifica che la decifratura produca "testo di prova". La chiave "YELLOW SUBMARINE" è quella canonica delle sfide Cryptopals.

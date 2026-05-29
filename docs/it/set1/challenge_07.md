---
layout: default
title: "Sfida 7 — AES in modalità ECB"
parent: "Set 1 IT"
grand_parent: IT
nav_order: 7
permalink: /it/set1/challenge_07/
lang: it
---

# Sfida 7 — AES in modalità ECB

[← Sfida precedente](../challenge_06/) · [Sfida successiva →](../challenge_08/) · [🇬🇧 English](../../../en/set1/challenge_07/) · [Set 1](../) · [Home](../../)

---

## Teoria

AES (Advanced Encryption Standard) è il cifrario a blocchi simmetrico standard de facto adottato dal NIST nel 2001 dopo un concorso pubblico. AES opera su blocchi di 128 bit (16 byte) con chiavi da 128, 192 o 256 bit. L'algoritmo interno prevede 10, 12 o 14 round di trasformazioni (SubBytes, ShiftRows, MixColumns, AddRoundKey) che garantiscono confusione e diffusione.

La modalità ECB (Electronic CodeBook) è il modo più semplice per usare un cifrario a blocchi: ogni blocco di 16 byte del testo in chiaro viene cifrato indipendentemente dagli altri usando la stessa chiave. La semplicità è il punto di forza (facilmente parallelizzabile, errori di bit non si propagano tra blocchi) ma anche il principale difetto: blocchi identici di testo in chiaro producono blocchi identici di testo cifrato. Questo significa che la struttura del testo in chiaro è parzialmente visibile nel testo cifrato: se un'immagine è cifrata in ECB, si può ancora distinguerne i contorni e i pattern (il famoso "ECB penguin").

Per questo motivo, ECB non dovrebbe mai essere usato in pratica per cifrare più di un blocco di dati. Tuttavia, è un mattone fondamentale per le modalità più sicure: CBC usa ECB internamente (con l'aggiunta dello XOR col blocco precedente), e CTR usa ECB per generare il keystream.

In questa sfida, AES-ECB viene usato per decifrare un testo cifrato reale usando la chiave "YELLOW SUBMARINE". L'implementazione usa la libreria OpenSSL tramite il crate `openssl`.

## Concetti chiave

- **AES**: cifrario a blocchi simmetrico con blocchi da 128 bit, standard NIST dal 2001.
- **Modalità ECB**: ogni blocco è cifrato indipendentemente; blocchi identici producono cifrati identici.
- **PKCS#7 padding**: schema di riempimento che porta il testo in chiaro a lunghezza multipla del blocco.
- **`ssl_ecb_decrypt`**: metodo del trait `CryptoVec` che usa OpenSSL per decifrare con AES-128-ECB.
- **Crate `openssl`**: binding Rust per la libreria crittografica OpenSSL, usata per le primitive AES.
- **Chiave simmetrica**: la stessa chiave è usata per cifrare e decifrare.

## Spiegazione del codice

### Struttura generale

La sfida usa `src/cryptovec/mod.rs`, specificamente `ssl_ecb_decrypt`, che delega a OpenSSL tramite il crate `openssl`. Il test usa anche `src/base64/mod.rs` per decodificare il testo cifrato da Base64.

### Implementazione

`ssl_ecb_decrypt` usa le API di OpenSSL:

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

Il processo è in tre fasi: creazione del `Crypter` con la modalità, la chiave e l'IV (None per ECB); chiamata a `update` per processare i dati; chiamata a `finalize` per gestire il padding finale. Il buffer di output è allocato con `self.len() + cipher.block_size()` per avere spazio sufficiente.

Il parametro `pad: Option<bool>` controlla se OpenSSL deve rimuovere automaticamente il padding PKCS#7 durante la decifratura. Con `Some(true)` (default), il padding viene rimosso. Con `Some(false)`, i byte di padding rimangono nel risultato.

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

Il test decifra una stringa Base64 con la chiave "YELLOW SUBMARINE" e verifica che il risultato sia "testo di prova". Nota che il test usa un testo di prova italiano invece del contenuto originale Cryptopals, mantenendo la struttura dell'esercizio.

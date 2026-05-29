---
layout: default
title: "Sfida 1 — Converti hex in base64"
parent: "Set 1 — IT"
nav_order: 1
permalink: /set1/it/challenge_01/
lang: it
---

# Sfida 1 — Converti hex in base64

[Sfida successiva →](../challenge_02/) · [🇬🇧 English](../../en/challenge_01/) · [Indice Set 1](../)

---

## Teoria

La codifica è uno strumento fondamentale nella crittografia moderna: non cifra i dati, ma li rappresenta in un formato diverso per la trasmissione o l'archiviazione. Le due codifiche più diffuse per i dati binari sono la notazione esadecimale (hex) e Base64.

La notazione esadecimale rappresenta ogni byte come due caratteri ASCII scelti dall'insieme `0–9, a–f`. Un byte con valore decimale 255 diventa quindi `ff`. Questa rappresentazione è intuitiva per i programmatori perché la corrispondenza con i bit è diretta: ogni nibble (4 bit) corrisponde a un singolo carattere hex. Di conseguenza, una sequenza di N byte richiede esattamente 2N caratteri hex.

Base64 è una codifica più compatta: rappresenta ogni gruppo di 3 byte (24 bit) come 4 caratteri ASCII scelti da un alfabeto di 64 simboli (`A–Z`, `a–z`, `0–9`, `+`, `/`). Il rapporto di espansione è 4/3, inferiore al 2/1 dell'hex. Il padding con `=` allinea l'output quando il numero di byte non è multiplo di 3. Base64 è onnipresente: compare nelle email (MIME), nei certificati X.509, nei cookie di sessione, nelle API REST che trasportano dati binari.

La sfida 1 delle Cryptopals è deliberatamente semplice: si tratta di convertire una stringa hex in Base64, dimostrando di saper gestire correttamente i livelli di rappresentazione dei dati. Questo esercizio è fondamentale perché tutte le sfide successive usano intensivamente entrambe le codifiche. Un errore di conversione all'inizio porterebbe a output incomprensibili e difficili da diagnosticare.

In Rust, la gestione degli errori tramite `Result<T, E>` rende esplicito ogni passo di conversione che può fallire. Questa chiarezza, assente in molti linguaggi dinamici, aiuta a ragionare sui casi limite come stringhe hex di lunghezza dispari o caratteri non validi.

## Concetti chiave

- **Hex (esadecimale):** codifica di byte come coppie di caratteri `0–9a–f`; 2 caratteri per byte.
- **Base64:** codifica di 3 byte in 4 caratteri ASCII; usata per trasportare dati binari in contesti testuali.
- **Nibble:** metà di un byte (4 bit); un carattere hex corrisponde a un nibble.
- **Padding Base64:** carattere `=` aggiunto per allineare l'output a multipli di 4 caratteri.
- **`Result<T, E>`:** tipo Rust per gestire esplicitamente successo ed errore senza eccezioni.
- **Invariante di rappresentazione:** stessi byte sottostanti, codifica superficiale diversa.

## Spiegazione del codice

### Struttura generale

La sfida coinvolge due moduli: `src/hex/mod.rs` (struttura `Hex`) e `src/base64/mod.rs` (struttura `Base64`). Il test in `src/set1.rs` crea un `Hex` da una stringa, lo converte in `Base64`, e confronta il risultato con il valore atteso.

### Implementazione

La struttura `Hex` è un newtype intorno a `String`:

```rust
pub struct Hex(pub String);
```

Il costruttore `from_string` valida l'input prima di wrapparlo:

```rust
pub fn from_string(s: String) -> Result<Hex, JlmCryptoErrors> {
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(JlmCryptoErrors::InvalidHEXValue);
    }
    if s.len() % 2 != 0 {
        return Err(JlmCryptoErrors::InvalidHEXValue);
    }
    Ok(Hex(s))
}
```

La validazione ha due passi: prima verifica che ogni carattere sia un cifra hex valida con `is_ascii_hexdigit()`, poi controlla che la lunghezza sia pari (ogni byte richiede esattamente 2 caratteri hex). Se uno dei due controlli fallisce, viene restituito `JlmCryptoErrors::InvalidHEXValue`.

Il metodo `to_bytes` converte la stringa hex in un vettore di byte:

```rust
pub fn to_bytes(&self) -> Result<Vec<u8>, JlmCryptoErrors> {
    let mut result = Vec::new();
    for i in (0..self.0.len()).step_by(2) {
        let byte_str = &self.0[i..i + 2];
        match u8::from_str_radix(byte_str, 16) {
            Ok(byte) => result.push(byte),
            Err(_) => return Err(JlmCryptoErrors::InvalidHEXToBytesConversion),
        }
    }
    Ok(result)
}
```

Questo metodo itera sulla stringa a passi di 2, prende ogni coppia di caratteri con lo slice `&self.0[i..i+2]`, e la converte in `u8` usando `u8::from_str_radix(byte_str, 16)`. La base 16 corrisponde al sistema esadecimale. Qualsiasi errore di parsing viene propagato come `Err`.

Il metodo principale per questa sfida è `to_base64` su `Hex`:

```rust
pub fn to_base64(&self) -> Result<Base64, JlmCryptoErrors> {
    match &self.to_bytes() {
        Ok(v) => {
            const BASE64_CHARS: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut result = String::new();
            for chunk in v.chunks(3) {
                let b1 = chunk[0];
                let b2 = if chunk.len() > 1 { chunk[1] } else { 0 };
                let b3 = if chunk.len() > 2 { chunk[2] } else { 0 };
                let n = ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);
                result.push(BASE64_CHARS[((n >> 18) & 63) as usize] as char);
                result.push(BASE64_CHARS[((n >> 12) & 63) as usize] as char);
                if chunk.len() > 1 {
                    result.push(BASE64_CHARS[((n >> 6) & 63) as usize] as char);
                } else {
                    result.push('=');
                }
                if chunk.len() > 2 {
                    result.push(BASE64_CHARS[(n & 63) as usize] as char);
                } else {
                    result.push('=');
                }
            }
            Ok(Base64::from_string(result))
        }
        Err(_) => Err(JlmCryptoErrors::InvalidHEXToBase64Conversion),
    }
}
```

Prima converte i byte hex ottenuti da `to_bytes()`. Poi itera in chunk da 3 byte: i tre byte vengono compattati in un intero a 32 bit con shift e OR bitwise. I 24 bit vengono poi estratti in quattro gruppi da 6 bit con shift e mask `& 63` (che è `0b111111`), ognuno usato come indice nell'alfabeto Base64. Se il chunk ha meno di 3 byte, il carattere di padding `=` sostituisce i caratteri mancanti.

### Il test

```rust
#[test]
fn challenge_1() {
    assert_eq!(
        Hex::from_string(String::from(
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        ))
        .unwrap()
        .to_base64()
        .unwrap(),
        Base64::from_string(String::from(
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        ))
    );
}
```

Il test costruisce un `Hex` dalla stringa fornita, chiama `.to_base64()` e confronta il risultato con il `Base64` atteso usando `PartialEq`. I `.unwrap()` trasformano gli errori in panic — appropriato nei test. La stringa hex decodifica in ASCII "I'm killing your brain like a poisonous mushroom", la famosa frase di apertura delle Cryptopals.

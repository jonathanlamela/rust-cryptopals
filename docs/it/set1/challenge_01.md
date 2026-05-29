---
layout: default
title: "Sfida 1 — Converti hex in Base64"
parent: "Set 1 IT"
grand_parent: IT
nav_order: 1
permalink: /it/set1/challenge_01/
lang: it
---

# Sfida 1 — Converti hex in Base64

[Sfida successiva →](../challenge_02/) · [🇬🇧 English](../../../en/set1/challenge_01/) · [Set 1](../) · [Home](../../)

---

## Teoria

La codifica esadecimale (hex) e la codifica Base64 sono due dei sistemi di rappresentazione binaria più diffusi nell'informatica e nella crittografia. La notazione esadecimale usa sedici simboli (0–9, a–f) per rappresentare ogni nibble di quattro bit: ogni byte viene quindi espresso come coppia di caratteri hex, per un totale di due caratteri per byte. Questo formato è leggibile dagli sviluppatori, compatto e reversibile senza perdita di informazioni.

Base64, al contrario, fu progettata per trasportare dati binari arbitrari attraverso canali che accettano solo testo ASCII a sette bit, come le email SMTP o gli URL. L'algoritmo prende tre byte (24 bit) alla volta e li suddivide in quattro gruppi da sei bit ciascuno. Ogni gruppo di sei bit viene poi mappato su uno dei 64 caratteri del vocabolario Base64: A–Z (0–25), a–z (26–51), 0–9 (52–61), + (62) e / (63). Se il numero di byte originali non è divisibile per tre, si aggiungono uno o due caratteri di padding `=` per completare l'ultimo gruppo di quattro caratteri. Il risultato è una stringa circa il 33% più lunga dei dati originali, ma completamente compatibile con qualsiasi sistema che accetti testo ASCII.

La conversione da hex a Base64 richiede due passaggi: prima si convertono le coppie di caratteri hex in byte, poi si applica la codifica Base64 ai byte ottenuti. In Rust, questa catena di operazioni è particolarmente elegante grazie al sistema di tipi e ai metodi incatenati. L'intera operazione è deterministicadica: dati gli stessi byte in ingresso, la codifica Base64 produrrà sempre la stessa stringa.

Capire queste due codifiche è fondamentale per la crittografia pratica, perché quasi ogni protocollo di sicurezza — TLS, JWT, SSH, PGP — usa hex o Base64 per serializzare chiavi, certificati e dati cifrati.

## Concetti chiave

- **Notazione esadecimale**: sistema posizionale in base 16 che usa i simboli 0–9 e a–f per rappresentare nibble da 4 bit.
- **Base64**: codifica che mappa 3 byte (24 bit) in 4 caratteri ASCII, usando un alfabeto di 64 simboli sicuri per il testo.
- **Padding Base64**: carattere `=` aggiunto alla fine per portare l'output a lunghezza multipla di 4 caratteri.
- **Nibble**: metà di un byte (4 bit), unità base della rappresentazione hex.
- **Rappresentazione binaria**: la codifica non modifica i dati sottostanti, ne cambia solo la rappresentazione testuale.
- **Struct `Hex`**: tipo Rust che incapsula una stringa hex con validazione e metodi di conversione.
- **Struct `Base64`**: tipo Rust che incapsula una stringa Base64 con costruttori da stringa e da slice di byte.

## Spiegazione del codice

### Struttura generale

La sfida coinvolge due moduli principali: `src/hex/mod.rs` che definisce la struct `Hex`, e `src/base64/mod.rs` che definisce la struct `Base64`. Il test in `src/set1.rs` collega le due strutture attraverso la catena di metodi `from_string` → `to_base64`.

### Implementazione

Il punto di ingresso è `Hex::from_string`, che accetta una `String` e ne valida il contenuto:

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

Il metodo usa `.chars().all()` per garantire che ogni carattere sia un cifra hex valida (0–9, a–f, A–F). Controlla anche la parità della lunghezza, necessaria perché ogni byte richiede esattamente due caratteri hex. Se la validazione passa, costruisce il valore `Hex(s)` — un newtype pattern che avvolge la `String` grezza.

Successivamente, `to_base64` orchestra la conversione completa:

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

Prima chiama `to_bytes()` per convertire le coppie hex in byte. Poi processa i byte a chunk di 3: combina i tre byte in un intero a 32 bit usando shift e OR bitwise, quindi estrae quattro indici da 6 bit con maschere `& 63`. Ogni indice indicizza l'array `BASE64_CHARS`. Se il chunk finale ha meno di 3 byte, i byte mancanti vengono trattati come zero e i caratteri corrispondenti sono sostituiti con `=`.

Il metodo `to_bytes` converte la stringa hex in `Vec<u8>`:

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

Itera con step 2, estraendo ogni coppia di caratteri come slice di stringa e convertendola in un `u8` con `from_str_radix(..., 16)`.

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

Il test crea un `Hex` dalla stringa di input, chiama `.to_base64()`, e confronta il risultato con il valore Base64 atteso usando `assert_eq!`. Entrambi i lati implementano `PartialEq` per confronto diretto. La stringa hex decodifica il testo ASCII "I'm killing your brain like a poisonous mushroom".

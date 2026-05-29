---
layout: default
title: "Sfida 9 — Padding PKCS#7"
parent: "Set 2 IT"
grand_parent: IT
nav_order: 1
permalink: /it/set2/challenge_09/
lang: it
---

# Sfida 9 — Padding PKCS#7

[Sfida successiva →](../challenge_10/) · [🇬🇧 English](../../../en/set2/challenge_09/) · [Set 2](../) · [Home](../../)

---

## Teoria

I cifrari a blocchi come AES richiedono che il testo in chiaro abbia una lunghezza esatta multipla della dimensione del blocco (16 byte per AES-128). Nella pratica, i messaggi raramente hanno lunghezze così precise. Il padding è il meccanismo che risolve questo problema: aggiunge byte extra alla fine del messaggio per portarlo alla lunghezza richiesta.

PKCS#7 (Public Key Cryptography Standards #7) è lo schema di padding più usato. La regola è semplice e ingegnosa: se il messaggio ha bisogno di P byte di padding (con 1 ≤ P ≤ block_size), si aggiungono esattamente P byte, ognuno con il valore P. Se il messaggio è già lungo un multiplo esatto del blocco, si aggiunge un blocco intero di padding con tutti i byte al valore block_size (16 per AES). Questo secondo caso è necessario per garantire che il padding possa sempre essere rimosso univocamente: il ricevitore legge sempre l'ultimo byte, interpreta il suo valore come numero di byte di padding, e li rimuove.

Esempi:
- "YELLOW SUBMARINE" (16 byte) → "YELLOW SUBMARINE\x10\x10...\x10" (32 byte, 16 byte di padding con valore 16)
- "YELLOW SUBMARIN" (15 byte) → "YELLOW SUBMARIN\x01" (16 byte, 1 byte di padding con valore 1)
- "HELLO" (5 byte) con blocco 8 → "HELLO\x03\x03\x03" (8 byte, 3 byte di padding con valore 3)

La verifica del padding è altrettanto importante: durante la decifratura si deve controllare che i byte di padding siano tutti uguali al loro valore. Se il padding non è valido, il messaggio è corrotto o è stato manomesso. Questa verifica è alla base del "padding oracle attack" della sfida 17.

## Concetti chiave

- **PKCS#7**: schema di padding che aggiunge P byte di valore P per portare il messaggio a lunghezza multipla del blocco.
- **Blocco AES**: 16 byte; il padding porta sempre a lunghezza multipla di 16.
- **Padding obbligatorio**: anche messaggi già lunghi un multiplo del blocco ricevono un blocco completo di padding.
- **`pad`**: metodo del trait `CryptoVec` che aggiunge padding PKCS#7 in-place.
- **`unpad`**: metodo del trait `CryptoVec` che rimuove il padding PKCS#7 verificandone la validità.
- **`check_padding_valid`**: metodo che verifica la validità del padding senza rimuoverlo.

## Spiegazione del codice

### Struttura generale

La sfida usa `src/cryptovec/mod.rs`, specificamente i metodi `pad`, `unpad` e `check_padding_valid` del trait `CryptoVec` implementato su `Vec<u8>`.

### Implementazione

`pad` aggiunge il padding PKCS#7:

```rust
fn pad(&mut self, k: u8) -> Result<bool, JlmCryptoErrors> {
    if k < 2 {
        return Err(JlmCryptoErrors::PKCS7PaddingFailed);
    }
    let p = k - (self.len() % k as usize) as u8;
    for _ in 0..p {
        self.push(p);
    }
    Ok(true)
}
```

Calcola il numero di byte di padding necessari: `k - (len % k)`. Se `len % k == 0`, il risultato è `k` (blocco intero di padding). Se `len % k == r`, il risultato è `k - r`. Poi aggiunge esattamente `p` byte ognuno con valore `p`.

`check_padding_valid` verifica che il padding sia corretto:

```rust
fn check_padding_valid(&self, k: u8) -> Result<bool, JlmCryptoErrors> {
    if k < 2 { return Err(JlmCryptoErrors::InvalidPadding); }
    if self.is_empty() || self.len() % k as usize != 0 {
        return Err(JlmCryptoErrors::InvalidPadding);
    }
    let padding = self[self.len() - 1];
    if !(1 <= padding && padding <= k) {
        return Err(JlmCryptoErrors::InvalidPadding);
    }
    let is_valid = self[self.len() - padding as usize..]
        .iter()
        .all(|&b| b == padding);
    if is_valid { Ok(true) } else { Err(JlmCryptoErrors::InvalidPadding) }
}
```

Legge l'ultimo byte come valore di padding, verifica che sia nell'intervallo [1, k], poi controlla che tutti gli ultimi `padding` byte abbiano lo stesso valore.

### Il test

```rust
#[test]
fn challenge_9() {
    let size = 20;
    let mut string_to_pad = b"YELLOW SUBMARINE".to_vec();
    string_to_pad.pad(size).unwrap();
    assert_eq!(
        &string_to_pad,
        [89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4].as_ref()
    )
}
```

"YELLOW SUBMARINE" è 16 byte. Con blocco di 20, il padding necessario è `20 - (16 % 20) = 4`. Quindi vengono aggiunti 4 byte di valore 4 (0x04). Il test verifica byte per byte il risultato atteso.

---
layout: default
title: "Sfida 15 — Validazione padding PKCS#7"
parent: "Set 2 — IT"
nav_order: 7
permalink: /set2/it/challenge_15/
lang: it
---

# Sfida 15 — Validazione padding PKCS#7

[← Sfida precedente](../challenge_14/) · [Sfida successiva →](../challenge_16/) · [🇬🇧 English](../../en/challenge_15/) · [Indice Set 2](../../)

---

## Teoria

La validazione del padding PKCS#7 è più sottile di quanto sembri. Un'implementazione naïve controlla solo l'ultimo byte e rimuove quel numero di byte senza verificare che tutti i byte di padding abbiano il valore corretto. Questo errore crea una vulnerabilità: l'attaccante può iniettare byte di padding invalidi che vengono accettati, alterando il plaintext.

La validazione corretta richiede tre controlli: (1) il vettore non è vuoto e la sua lunghezza è un multiplo della dimensione del blocco; (2) l'ultimo byte ha un valore tra 1 e la dimensione del blocco; (3) tutti gli ultimi N byte (dove N è il valore dell'ultimo byte) hanno il valore N.

La sfida 17 (padding oracle) sfrutta esattamente questa validazione: l'oracle accetta il ciphertext e restituisce se il padding è valido o meno, permettendo all'attaccante di dedurre il plaintext byte per byte.

Il test in questa sfida dimostra tre casi: padding valido (`\x04\x04\x04\x04`), padding con valore sbagliato (`\x05\x05\x05\x05` alla fine di un testo diverso), e rimozione corretta del padding.

## Concetti chiave

- **Validazione rigorosa del padding:** tutti gli ultimi N byte devono avere il valore N.
- **`check_padding_valid`:** restituisce `Ok(true)` o `Err(InvalidPadding)`.
- **`unpad`:** rimuove il padding dopo la validazione.
- **Timing attacks:** un'implementazione scorretta che esce presto può rivelare informazioni attraverso i tempi di risposta.
- **Padding oracle:** il risultato di `check_padding_valid` è l'oracolo della sfida 17.
- **`JlmCryptoErrors::InvalidPadding`:** errore tipo usato per segnalare padding non valido.

## Spiegazione del codice

### Struttura generale

I metodi `check_padding_valid` e `unpad` sono nel trait `CryptoVec` in `src/cryptovec/mod.rs`. Già descritti nella sfida 9, qui vengono testati in modo più approfondito.

### Implementazione

`check_padding_valid` (già mostrato nella sfida 9) controlla che:
- Il vettore non sia vuoto e sia multiplo di k.
- L'ultimo byte `padding` sia in `[1, k]`.
- Tutti i byte `self[self.len() - padding..]` abbiano valore `padding`.

Un dettaglio importante: il metodo restituisce `Err` per padding invalido, non `Ok(false)`. Questo permette l'uso dell'operatore `?` per la propagazione degli errori e rende esplicita la semantica dell'errore di padding — fondamentale per l'attacco padding oracle della sfida 17.

### Il test

```rust
#[test]
pub fn challenge_15() {
    let str1 = String::from("ICE ICE BABY\x04\x04\x04\x04");
    let str2 = String::from("ICE ICE BABY\x05\x05\x05\x05");
    let str3 = String::from("ICE ICE BABY\x05\x05\x05\x05");

    let mut str1_vec = str1.as_bytes().to_vec();
    let str2_vec = str2.as_bytes().to_vec();
    let str3_vec = str3.as_bytes().to_vec();

    assert_eq!(str1_vec.check_padding_valid(16).unwrap(), true);
    assert_eq!(str2_vec.check_padding_valid(16).is_err(), true);
    assert_eq!(str3_vec.check_padding_valid(16).is_err(), true);

    let _ = str1_vec.unpad(16);
    assert_eq!(String::from_utf8(str1_vec).unwrap(), "ICE ICE BABY");
}
```

`str1` ha padding valido: 4 byte con valore 4. La stringa ha 16 byte totali (12 + 4), multiplo di 16. `str2` e `str3` hanno 4 byte con valore 5, ma "ICE ICE BABY" ha 12 byte e 5 byte di padding porterebbero a 17 byte — non multiplo di 16, ma anche i byte di padding hanno valore 5 mentre ne servirebbero con valore 4. Entrambi falliscono. Dopo `unpad`, `str1_vec` diventa "ICE ICE BABY".

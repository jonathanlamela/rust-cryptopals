---
layout: default
title: "Sfida 11 — Oracle ECB/CBC"
parent: "Set 2 IT"
grand_parent: IT
nav_order: 3
permalink: /it/set2/challenge_11/
lang: it
---

# Sfida 11 — Oracle ECB/CBC

[← Sfida precedente](../challenge_10/) · [Sfida successiva →](../challenge_12/) · [🇬🇧 English](../../../en/set2/challenge_11/) · [Set 2](../) · [Home](../../)

---

## Teoria

Un oracolo crittografico è un sistema che esegue operazioni crittografiche e restituisce il risultato all'attaccante, ma mantiene la chiave segreta. In questa sfida, l'oracolo sceglie casualmente se cifrare in ECB o CBC, aggiunge un prefisso e un suffisso casuali al testo in chiaro, e restituisce il cifrato. Il compito è determinare quale modalità è stata usata osservando solo il testo cifrato.

Il principio di rilevamento è lo stesso della sfida 8: ECB produce blocchi identici per blocchi identici di testo in chiaro. Se forniamo un input sufficientemente lungo e ripetitivo (ad esempio, 48 byte tutti uguali), i byte ripetuti occuperanno almeno due blocchi consecutivi nel testo in chiaro dopo l'aggiunta del prefisso (che può avere lunghezza fino a 10 byte). Con ECB, questi due blocchi in chiaro identici produrranno blocchi cifrati identici; con CBC, non lo faranno (grazie al chaining).

L'uso di input ripetitivi è una tecnica fondamentale nella crittanalisi degli oracoli di cifratura. Nei set successivi, questa tecnica sarà affinata per estrarre informazioni byte per byte su dati segreti (sfide 12 e 14).

Il random oracle della sfida 11 usa `CustomCrypter11`, che sceglie casualmente ECB o CBC, genera chiave e IV casuali, e aggiunge un prefisso e un suffisso casuali (5–10 byte) al testo in chiaro.

## Concetti chiave

- **Oracolo di cifratura**: sistema che cifra input forniti dall'attaccante rivelando il cifrato ma non la chiave.
- **Rilevamento ECB via blocchi ripetuti**: tecnica che sfrutta la proprietà deterministica di ECB per rilevarne l'uso.
- **`CustomCrypter11`**: struct che simula un oracolo con modalità ECB o CBC scelta casualmente.
- **`OracleBase`**: struct che contiene chiave, IV, prefisso, suffisso e modalità, con un metodo `encrypt` generico.
- **`is_ecb_calculated`**: metodo che controlla se due blocchi consecutivi del cifrato sono identici.
- **Testo in chiaro ripetitivo**: input di 48 byte tutti uguali usato per garantire blocchi ripetuti dopo l'aggiunta del prefisso.

## Spiegazione del codice

### Struttura generale

La sfida usa `src/crypters/custom_crypter_11.rs` per l'oracolo e `src/oracle/base.rs` per la logica di cifratura condivisa. Il trait `Oracle` in `src/oracle/mod.rs` definisce il contratto.

### Implementazione

`CustomCrypter11::new()` costruisce l'oracolo con parametri casuali:

```rust
pub fn new() -> Result<Self, JlmCryptoErrors> {
    let mut random_generator = thread_rng();
    let mut cipher: Cipher = Cipher::aes_128_ecb();
    let mode: MODE = if random_generator.gen() {
        MODE::ECB
    } else {
        cipher = Cipher::aes_128_cbc();
        MODE::CBC
    };
    let key = cipher.block_size().random_block();
    let prefix: Vec<u8> = random_generator.gen_range(5..=10).random_block();
    let suffix: Vec<u8> = random_generator.gen_range(5..=10).random_block();
    let iv: Option<Vec<u8>> = if mode == MODE::CBC {
        Some(cipher.block_size().random_block())
    } else {
        None
    };
    Ok(CustomCrypter11 { base: OracleBase { key, prefix: Some(prefix), suffix: Some(suffix), mode, iv } })
}
```

`is_ecb_calculated` verifica se due blocchi del cifrato sono identici:

```rust
pub fn is_ecb_calculated(&self, vec: Vec<u8>) -> Result<bool, JlmCryptoErrors> {
    let blocks: Vec<&[u8]> = vec.chunks(16).skip(1).take(2).collect();
    Ok(blocks[0] == blocks[1])
}
```

Salta il primo blocco (che contiene il prefisso) e confronta il secondo e il terzo blocco. Con 48 byte di input tutti uguali e un prefisso di al massimo 10 byte, i blocchi 1 e 2 (0-indexed) conterranno sempre byte identici se la modalità è ECB.

### Il test

```rust
#[test]
pub fn challenge_11() {
    let oracle = CustomCrypter11::new();
    match oracle {
        Ok(r) => {
            let input: Vec<u8> = vec![0; 48];
            let encrypted_value = r.base.encrypt(&input).unwrap();
            if r.is_cbc() {
                assert_eq!(r.is_ecb_calculated(encrypted_value).unwrap(), false);
            } else if r.is_ecb() {
                assert_eq!(r.is_ecb_calculated(encrypted_value).unwrap(), true);
            }
        }
        Err(_) => panic!(),
    }
}
```

Il test verifica che la rilevazione di ECB/CBC sia coerente con la modalità effettivamente usata dall'oracolo.

---
layout: default
title: "Sfida 5 — Implementa XOR a chiave ripetuta"
parent: "Set 1 — IT"
nav_order: 5
permalink: /set1/it/challenge_05/
lang: it
---

# Sfida 5 — Implementa XOR a chiave ripetuta

[← Sfida precedente](../challenge_04/) · [Sfida successiva →](../challenge_06/) · [🇬🇧 English](../../en/challenge_05/) · [Indice Set 1](../../)

---

## Teoria

Il cifrario XOR a chiave ripetuta, noto anche come cifrario di Vigenère nel dominio dei byte, è un'estensione del cifrario XOR a singolo byte. Invece di usare un solo byte come chiave, si usa una sequenza di byte di lunghezza fissa che viene ripetuta ciclicamente per coprire l'intero plaintext. Ogni byte del plaintext viene XORato con il corrispondente byte della chiave ciclica.

Storicamente, il cifrario di Vigenère (sulla versione testuale) era considerato inviolabile per secoli — veniva chiamato "le chiffre indéchiffrable". La sua rottura da parte di Charles Babbage e Friedrich Kasiski nel XIX secolo fu un traguardo fondamentale nella crittoanalisi. L'attacco si basa sul fatto che blocchi di plaintext identici che si allineano con la stessa porzione di chiave producono blocchi di ciphertext identici, rivelando la lunghezza della chiave e permettendo di decomporre il problema in una serie di cifrari monoalfabetici.

Nel dominio dei byte, lo stesso principio si applica: se la chiave è "ICE" (3 byte), il byte i del plaintext viene XORato con la chiave `key[i % 3]`. La ripetizione ciclica crea pattern statistici che possono essere sfruttati dall'analisi delle frequenze, come mostrato nella sfida 6.

In Rust, il pattern `cycle()` su un iteratore permette di creare un iteratore infinito che ripete la sequenza originale. Questo è un approccio idiomatico e sicuro rispetto all'uso di indici manuali con modulo, che potrebbe portare a bug di off-by-one.

## Concetti chiave

- **Cifrario di Vigenère (byte):** XOR di ogni byte con il corrispondente byte della chiave ciclica.
- **Chiave ciclica:** la chiave di N byte viene ripetuta fino a coprire l'intero messaggio.
- **`cycle()`:** iteratore Rust che ripete infinitamente la sequenza sottostante.
- **Cifrario polialfabetico:** usa alfabeti multipli in modo ciclico (uno per ogni posizione nella chiave).
- **Vulnerabilità statistica:** pattern nel ciphertext rivelano la lunghezza della chiave.
- **`zip` su iteratori:** accoppia due iteratori per operazioni elemento per elemento.

## Spiegazione del codice

### Struttura generale

La sfida usa il metodo `repeating_key_xor` del trait `CryptoVec` in `src/cryptovec/mod.rs`. Il test in `src/set1.rs` cifra un plaintext noto con una chiave nota e confronta il risultato con il ciphertext atteso in formato hex.

### Implementazione

Il metodo `repeating_key_xor`:

```rust
fn repeating_key_xor(&self, key: &[u8]) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    let mut key_iterator = key.into_iter().cycle();
    for i in self.into_iter() {
        result.push(key_iterator.next().unwrap() ^ i);
    }
    result
}
```

`key.into_iter().cycle()` crea un iteratore infinito che scorre i byte della chiave ciclicamente: quando arriva alla fine della chiave, ricomincia dall'inizio. `key_iterator.next().unwrap()` preleva il prossimo byte della chiave — l'`unwrap` è sicuro perché `cycle()` produce un iteratore infinito, quindi `next()` non restituisce mai `None`. Per ogni byte `i` del plaintext, si esegue XOR con il byte corrente della chiave ciclica.

La firma `&[u8]` per `key` accetta sia array che slice di byte (`b"ICE"` è un `&[u8; 3]` che può essere coercito a `&[u8]`).

### Il test

```rust
#[test]
fn challenge_5() {
    let expected_result = Hex::from_string(String::from(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    )).unwrap();
    let clear_text_as_bytes =
        b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".to_vec();
    let clear_key_as_bytes = b"ICE";

    let result = clear_text_as_bytes.repeating_key_xor(clear_key_as_bytes);
    let hex_result =
        Hex::from_bytes(result).unwrap_or_else(|_| panic!("Hex from bytes failed"));
    assert_eq!(expected_result, hex_result);
}
```

`b"..."` è un letterale byte in Rust: produce un `&[u8]` o `&[u8; N]`. `.to_vec()` crea un `Vec<u8>` dall'array. `b"ICE"` è la chiave di 3 byte. Il risultato viene convertito in hex e confrontato con il valore atteso.

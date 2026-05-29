---
layout: default
title: "Sfida 2 — XOR fisso"
parent: "Set 1 — IT"
nav_order: 2
permalink: /set1/it/challenge_02/
lang: it
---

# Sfida 2 — XOR fisso

[← Sfida precedente](../challenge_01/) · [Sfida successiva →](../challenge_03/) · [🇬🇧 English](../../en/challenge_02/) · [Indice Set 1](../)

---

## Teoria

L'operazione XOR (exclusive OR) è l'operazione binaria più importante in crittografia. Dati due bit, XOR restituisce 1 se e solo se i bit sono diversi; restituisce 0 se sono uguali. Questa semplice regola ha proprietà molto utili: è auto-inversa (`a XOR b XOR b = a`), commutativa e associativa. L'auto-inversione significa che la stessa operazione serve sia per cifrare che per decifrare, semplificando enormemente l'implementazione.

XOR bit-a-bit tra due sequenze di byte di uguale lunghezza produce una terza sequenza in cui ogni byte è il risultato di XOR tra i byte corrispondenti. Se uno degli operandi è segreto (la chiave), il risultato è unintelligibile a chi non conosce la chiave. Se invece entrambi gli operandi sono noti, XOR rivela l'altro — questo è il principio dietro molti attacchi crittografici.

Nel contesto delle Cryptopals, questa sfida serve da esercizio tecnico ma anticipa concetti critici: XOR su sequenze di uguale lunghezza è la base del one-time pad (OTP), l'unico cifrario teoricamente inviolabile. L'OTP richiede che la chiave sia almeno lunga quanto il messaggio, completamente casuale, e usata una sola volta. Se queste condizioni non sono rispettate — come nel cifrario XOR a chiave ripetuta delle sfide 5 e 6 — la sicurezza crolla.

XOR è anche alla base delle funzioni di feedback nei cifrari a blocchi (CBC usa XOR tra blocchi successivi) e dei cifrari a flusso (CTR mode usa XOR tra keystream e plaintext). Comprendere come funziona XOR a livello byte è quindi un prerequisito per tutte le sfide successive.

In Rust, `Vec<u8>` è il tipo naturale per sequenze di byte, e il trait `CryptoVec` definisce le operazioni crittografiche su di essi in modo ergonomico e sicuro.

## Concetti chiave

- **XOR (exclusive OR):** operazione bit-a-bit; `a XOR a = 0`, `a XOR 0 = a`, auto-inversa.
- **XOR fisso:** XOR tra due sequenze di byte della stessa lunghezza.
- **One-time pad (OTP):** cifrario teoricamente sicuro basato su XOR con chiave casuale usa-e-getta.
- **`Vec<u8>`:** tipo Rust per sequenze di byte mutabili allocate nell'heap.
- **Trait:** meccanismo di polimorfismo Rust; `CryptoVec` aggiunge metodi crittografici a `Vec<u8>`.
- **Propagazione degli errori:** pattern `unwrap_or_else` per convertire errori in panic con messaggio.

## Spiegazione del codice

### Struttura generale

La sfida usa `src/hex/mod.rs` per convertire stringhe hex in byte e `src/cryptovec/mod.rs` per eseguire l'operazione XOR. Il metodo `xor` è definito nel trait `CryptoVec` implementato su `Vec<u8>`.

### Implementazione

Il metodo `xor` nel trait `CryptoVec`:

```rust
fn xor(&self, v2: Vec<u8>) -> Vec<u8> {
    self.iter().zip(v2.iter()).map(|(&x, &y)| x ^ y).collect()
}
```

`self.iter()` produce un iteratore sul primo vettore. `.zip(v2.iter())` accoppia gli elementi dei due iteratori in tuple `(x, y)`. `.map(|(&x, &y)| x ^ y)` applica XOR a ogni coppia di byte — i pattern `&x` e `&y` fanno il dereferenziamento dei riferimenti restituiti dagli iteratori. `.collect()` materializza l'iteratore in un nuovo `Vec<u8>`. Il metodo consuma `v2` per valore (ownership) e prende `self` per riferimento: questa scelta di firma riflette la semantica dell'operazione (il secondo operando viene consumato, il primo viene letto).

La conversione hex → byte usa `Hex::from_string` e poi `to_bytes()`, entrambi già descritti nella sfida 1.

La conversione byte → hex usa `Hex::from_bytes`:

```rust
pub fn from_bytes(s: Vec<u8>) -> Result<Hex, JlmCryptoErrors> {
    let hex_string = s
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();
    Ok(Hex(hex_string))
}
```

`format!("{:02x}", byte)` formatta ogni byte come due cifre hex minuscole con zero di riempimento (`02` = minimo 2 cifre, `x` = hex minuscolo). Il risultato viene concatenato in una `String` tramite `collect::<String>()`.

### Il test

```rust
#[test]
fn challenge_2() {
    let hex1 = Hex::from_string(String::from("1c0111001f010100061a024b53535009181c")).unwrap();
    let hex2 = Hex::from_string(String::from("686974207468652062756c6c277320657965")).unwrap();

    let bytes1 = hex1.to_bytes().unwrap_or_else(|err| {
        panic!("Error converting from Hex to byte: {:?}", err);
    });
    let bytes2 = hex2.to_bytes().unwrap_or_else(|err| {
        panic!("Error converting from Hex to byte: {:?}", err);
    });

    let xor_result = bytes1.xor(bytes2);

    let expected_result =
        Hex::from_string(String::from("746865206b696420646f6e277420706c6179")).unwrap();

    let result = Hex::from_bytes(xor_result).unwrap();
    assert_eq!(result, expected_result);
}
```

Il test crea due valori `Hex`, li converte in byte con gestione degli errori tramite `unwrap_or_else`, esegue XOR, converte il risultato in `Hex` e confronta con il valore atteso. La stringa `746865206b696420646f6e277420706c6179` è l'hex ASCII di "the kid don't play".

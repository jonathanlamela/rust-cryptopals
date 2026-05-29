---
layout: default
title: "Sfida 3 — XOR a chiave singola"
parent: "Set 1 IT"
grand_parent: IT
nav_order: 3
permalink: /it/set1/challenge_03/
lang: it
---

# Sfida 3 — XOR a chiave singola

[← Sfida precedente](../challenge_02/) · [Sfida successiva →](../challenge_04/) · [🇬🇧 English](../../../en/set1/challenge_03/) · [Set 1](../) · [Home](../../)

---

## Teoria

Il cifrario XOR a chiave singola (single-byte XOR) è uno dei cifrari più semplici: ogni byte del messaggio viene combinato in XOR con lo stesso singolo byte di chiave. Nonostante la semplicità, questo cifrario è completamente insicuro perché è vulnerabile all'analisi della frequenza.

L'analisi della frequenza si basa sul fatto che nelle lingue naturali alcune lettere appaiono molto più spesso di altre. In inglese, la lettera 'e' ha una frequenza di circa il 12,7%, seguita da 't' (9,1%), 'a' (8,2%) e così via. Se cifriamo un testo inglese con XOR a byte singolo, la distribuzione delle frequenze nel cifrato sarà la stessa del testo in chiaro, solo spostata ciclicamente di una posizione (il valore della chiave). Un attaccante può quindi provare tutte e 256 le chiavi possibili, decifrare il testo per ognuna, calcolare un punteggio basato sulla frequenza delle lettere nel testo decifrato, e scegliere la chiave che produce il punteggio più alto.

Il punteggio può essere calcolato in vari modi: uno comune è sommare le frequenze logaritmiche delle lettere presenti nel testo decifrato. Usare i logaritmi ha il vantaggio di trasformare la moltiplicazione in addizione e di penalizzare pesantemente i caratteri non alfabetici (che spesso segnalano una decifrazione errata).

Questa tecnica — enumerare tutte le chiavi possibili, valutare ogni testo decifrato con una funzione di punteggio, e scegliere il massimo — è un attacco a forza bruta dello spazio delle chiavi combinato con un oracolo statistico. È la base degli attacchi alle sfide 4, 6 e 20.

## Concetti chiave

- **Single-byte XOR**: cifrario che applica XOR con un solo byte di chiave a tutto il messaggio.
- **Analisi della frequenza**: tecnica crittoanalitica che sfrutta la distribuzione non uniforme delle lettere nelle lingue naturali.
- **Punteggio linguistico**: funzione che assegna un punteggio a un array di byte in base alla plausibilità come testo in lingua naturale.
- **Spazio delle chiavi**: insieme di tutti i valori di chiave possibili (256 per un singolo byte).
- **Forza bruta**: attacco che enumera esaustivamente lo spazio delle chiavi.
- **`evaluate_frequency`**: metodo del trait `CryptoVec` che prova tutti i 256 byte come chiave e restituisce il testo decifrato con punteggio più alto.
- **`evaluate_score`**: metodo che calcola la somma dei logaritmi delle frequenze delle lettere in un array di byte.

## Spiegazione del codice

### Struttura generale

La sfida usa `src/cryptovec/mod.rs`, specificamente i metodi `evaluate_frequency`, `evaluate_score` e `xor_single` del trait `CryptoVec`.

### Implementazione

`xor_single` applica XOR con un singolo byte:

```rust
fn xor_single(&self, k: u8) -> Vec<u8> {
    self.iter().map(|x| x ^ k).collect()
}
```

Mappa ogni byte del vettore con l'operazione XOR contro la chiave `k`. Il risultato è un nuovo `Vec<u8>`.

`evaluate_score` calcola la plausibilità di un vettore come testo inglese:

```rust
fn evaluate_score(&self) -> Option<f64> {
    if !self.iter().all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace()) {
        return None;
    }
    Some(self.iter().fold(0.0, |score, b| {
        if b.is_ascii_alphabetic() {
            let i = b.to_ascii_lowercase() - b'a';
            score + LETTER_FREQUENCIES[usize::from(i)].log10()
        } else {
            score
        }
    }))
}
```

Prima filtra i vettori che contengono caratteri non stampabili — se anche un solo byte non è ASCII grafico o whitespace, restituisce `None`. Poi somma i logaritmi in base 10 delle frequenze inglesi per ogni carattere alfabetico. Il vettore delle frequenze è definito come costante `LETTER_FREQUENCIES: [f64; 26]`.

`evaluate_frequency` orchestra l'attacco completo:

```rust
fn evaluate_frequency(&self) -> Option<(f64, u8, Vec<u8>)> {
    let mut xors_vector: Vec<(u8, Vec<u8>)> = Vec::new();
    for key in 0..=255 {
        xors_vector.push((key, self.xor_single(key)));
    }
    let filtered_map = xors_vector.iter().filter_map(|row| {
        row.1.evaluate_score().map(|score| (score, row.0, row.1.clone()))
    });
    let max_value = filtered_map.max_by(|(a, _, _), (b, _, _)| a.partial_cmp(b).unwrap());
    max_value
}
```

Genera tutti i 256 possibili testi decifrati, filtra quelli che non producono un punteggio valido con `filter_map`, e restituisce la tripletta `(punteggio, chiave, testo)` con punteggio massimo.

### Il test

```rust
#[test]
fn challenge_3() {
    let result = Hex::from_string(String::from(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
    ))
    .unwrap()
    .to_bytes()
    .unwrap()
    .evaluate_frequency()
    .unwrap();
    let stringa = String::from_utf8(result.2).unwrap();
    assert_eq!(stringa, "Cooking MC's like a pound of bacon");
}
```

Il test converte la stringa hex in byte, chiama `evaluate_frequency`, estrae il testo dal terzo elemento della tripletta (`result.2`) e verifica che sia il testo atteso.

---
layout: default
title: "Sfida 20 — Rompi CTR a nonce fisso (statisticamente)"
parent: "Set 3 IT"
grand_parent: IT
nav_order: 4
permalink: /it/set3/challenge_20/
lang: it
---

# Sfida 20 — Rompi CTR a nonce fisso (statisticamente)

[← Sfida precedente](../challenge_19/) · [Sfida successiva →](../challenge_21/) · [🇬🇧 English](../../../en/set3/challenge_20/) · [Set 3](../) · [Home](../../)

---

## Teoria

La sfida 20 automatizza l'attacco della sfida 19 usando le stesse tecniche statistiche della sfida 6 (break repeating-key XOR). Il keystream fisso dei messaggi CTR con nonce fisso è matematicamente equivalente a una chiave ripetuta XOR: ogni messaggio alla posizione `i` è `C[i] = P[i] XOR K[i % key_len]`.

L'approccio automatizzato è la trasposizione: si raccolgono tutti i byte alla stessa posizione da tutti i messaggi, formando un "vettore colonna". Ogni vettore colonna è un insieme di byte tutti cifrati con lo stesso byte di keystream. Si applica l'analisi della frequenza delle lettere a ogni vettore colonna per trovare il byte di keystream più probabile. La chiave completa (keystream) si ottiene combinando i byte trovati per ogni posizione.

L'unica complicazione rispetto alla sfida 6 è che i messaggi hanno lunghezze diverse. La soluzione è troncare tutti i messaggi alla lunghezza del più corto — si perde un po' di copertura del keystream, ma si garantisce che ogni posizione abbia lo stesso numero di campioni.

Questo attacco è completamente automatizzato e non richiede intervento manuale, a differenza della sfida 19.

## Concetti chiave

- **Trasposizione**: riorganizzazione dei cifrati in vettori colonna, uno per ogni posizione del keystream.
- **Troncamento**: riduzione di tutti i messaggi alla lunghezza minima per uniformare le colonne.
- **`evaluate_frequency`**: attacco a byte singolo applicato a ogni colonna per trovare il byte di keystream.
- **Attacco automatizzato**: a differenza della sfida 19, l'intera analisi è eseguita programmaticamente.
- **`repeating_key_xor`**: usato per applicare il keystream trovato a tutti i cifrati concatenati.
- **Testi di Campbell**: i messaggi in chiaro sono tratti da canzoni rap codificate in Base64 nel file `data_20.txt`.

## Spiegazione del codice

### Struttura generale

La sfida usa `src/cryptovec/mod.rs` (`nonce_ctr_encrypt`, `evaluate_frequency`, `repeating_key_xor`) e legge da `data/data_20.txt`. L'attacco è interamente automatizzato nel test.

### Implementazione

Dopo la cifratura con nonce fisso (identica alla sfida 19), si trova la lunghezza minima:

```rust
let min = results.iter().map(|c| c.len()).min().unwrap();
for ciphertext in &mut results {
    ciphertext.truncate(min);
}
```

Si traspone la matrice dei cifrati:

```rust
let mut transposed: Vec<Vec<u8>> = vec![vec![]; min];
for string in &results {
    for i in 0..string.len() {
        let item = string[i];
        transposed[i].push(item);
    }
}
```

Per ogni colonna si applica `evaluate_frequency`:

```rust
let mut k_vec: Vec<u8> = Vec::new();
for bl in transposed {
    match bl.evaluate_frequency() {
        Some((_, key, _)) => k_vec.push(key),
        None => {}
    }
}
```

Si combina il keystream trovato con tutti i cifrati concatenati:

```rust
let flat_result: Vec<u8> = results.into_iter().flat_map(|f| f).collect();
let res = flat_result.repeating_key_xor(&k_vec);
let res_plain = String::from_utf8(res).unwrap();
assert!(res_plain.contains("I'm rated"));
```

### Il test

```rust
#[test]
pub fn challenge_20() {
    const BLOCK_SIZE: usize = 16;
    let key = BLOCK_SIZE.random_block();
    // lettura file, cifratura, trasposizione, attacco, verifica
    assert!(res_plain.contains("I'm rated"));
}
```

Il test verifica che il testo decifrato contenga la sottostringa "I'm rated", presente in uno dei testi di partenza.

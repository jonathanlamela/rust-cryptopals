---
layout: default
title: "Sfida 20 — Rompi CTR con nonce fisso (sostituzione)"
parent: "Set 3 — IT"
nav_order: 4
permalink: /set3/it/challenge_20/
lang: it
---

# Sfida 20 — Rompi CTR con nonce fisso (sostituzione)

[← Sfida precedente](../challenge_19/) · [🇬🇧 English](../../en/challenge_20/) · [Indice Set 3](../../)

---

## Teoria

La sfida 20 è la versione automatizzata e scalata della sfida 19. Invece di analizzare manualmente i ciphertext, si automatizza completamente l'attacco statistico: si tronca tutti i ciphertext alla lunghezza minima, si traspone la matrice di ciphertext per ottenere le "colonne", si applica `evaluate_frequency` su ogni colonna per trovare il byte di keystream più probabile, e si XORa l'intero corpus con il keystream trovato.

Questo approccio è formalmente equivalente all'attacco "break repeating-key XOR" della sfida 6, applicato al CTR con nonce fisso. La chiave ciclica è il keystream di lunghezza `min_length`: ogni byte del keystream è la chiave per quella "posizione" nel corpus di ciphertext.

Il risultato pratico è notevole: con abbastanza ciphertext e testi sufficientemente lunghi, è possibile recuperare il keystream e leggere i plaintext con buona accuratezza, senza mai conoscere la chiave AES. Questo illustra perché i protocolli crittografici moderni proibiscono esplicitamente il riutilizzo del nonce in CTR mode.

Il file `data_20.txt` contiene testi rap in Base64. Il test verifica che la stringa decifrata contenga "I'm rated" — una frase che compare nei testi originali.

## Concetti chiave

- **Troncamento alla lunghezza minima:** tutti i ciphertext vengono tagliati alla lunghezza del più corto.
- **Trasposizione della matrice di ciphertext:** raggruppa i byte per posizione di keystream.
- **Attacco XOR ciclico scalato:** equivalente alla sfida 6 applicata a un corpus di ciphertext.
- **`repeating_key_xor`:** usato per applicare il keystream trovato all'intero corpus.
- **`flat_map`:** trasforma `Vec<Vec<u8>>` in `Vec<u8>` concatenando tutti i ciphertext.
- **`data_20.txt`:** corpus di testi rap in Base64 (diverso da `data_19.txt`).

## Spiegazione del codice

### Struttura generale

Il test in `src/set3.rs` è completamente self-contained: legge il file, cifra con CTR, tronca, traspone, attacca, e verifica. Usa gli stessi primitivi delle sfide precedenti.

### Implementazione

Troncamento e trasposizione:

```rust
let min = results.iter().map(|c| c.len()).min().unwrap();
for ciphertext in &mut results {
    ciphertext.truncate(min);
}
let mut transposed: Vec<Vec<u8>> = vec![vec![]; min];
for string in &results {
    for i in 0..string.len() {
        let item = string[i];
        transposed[i].push(item);
    }
}
```

`min` è la lunghezza del ciphertext più corto. Dopo il troncamento, ogni ciphertext ha esattamente `min` byte. La trasposizione: per ogni posizione `i`, raccoglie il byte `i` da tutti i ciphertext nella colonna `transposed[i]`.

Attacco frequenziale:

```rust
let mut k_vec: Vec<u8> = Vec::new();
for bl in transposed {
    match bl.evaluate_frequency() {
        Some((_, key, _)) => k_vec.push(key),
        None => {}
    }
}
```

`evaluate_frequency` trova il byte di chiave più probabile per ogni colonna (posizione di keystream). Se non trova un candidato plausibile (None), quella posizione viene saltata — ma in pratica con abbastanza ciphertext questo non accade.

Decifratura dell'intero corpus:

```rust
let flat_result: Vec<u8> = results.into_iter().flat_map(|f| f).collect();
let res = flat_result.repeating_key_xor(&k_vec);
let res_plain = String::from_utf8(res).unwrap();
assert!(res_plain.contains("I'm rated"));
```

`flat_map` concatena tutti i ciphertext in un unico vettore. `repeating_key_xor` con `k_vec` decifra il tutto — il keystream si ripete ciclicamente sulla lunghezza del corpus, ma siccome tutti i ciphertext hanno la stessa lunghezza `min`, i byte del keystream sono allineati correttamente.

### Il test

```rust
#[test]
pub fn challenge_20() {
    const BLOCK_SIZE: usize = 16;
    let key = BLOCK_SIZE.random_block();
    let file_path = "./data/data_20.txt";
    let file = File::open(file_path).expect("Unable to read the file");
    let buf_reader = BufReader::new(file);
    let mut results: Vec<Vec<u8>> = Vec::new();
    for line in buf_reader.lines() {
        if line.is_ok() {
            let unwrapped_line = line.unwrap();
            let line_bytes = Base64::from_string(unwrapped_line);
            if let Ok(bytes) = line_bytes.to_bytes() {
                if let Ok(encrypt_result) = bytes.nonce_ctr_encrypt(&key, vec![0; 8]) {
                    results.push(encrypt_result);
                }
            }
        }
    }
    let min = results.iter().map(|c| c.len()).min().unwrap();
    for ciphertext in &mut results { ciphertext.truncate(min); }
    let mut transposed: Vec<Vec<u8>> = vec![vec![]; min];
    for string in &results {
        for i in 0..string.len() { transposed[i].push(string[i]); }
    }
    let mut k_vec: Vec<u8> = Vec::new();
    for bl in transposed {
        match bl.evaluate_frequency() {
            Some((_, key, _)) => k_vec.push(key),
            None => {}
        }
    }
    let flat_result: Vec<u8> = results.into_iter().flat_map(|f| f).collect();
    let res = flat_result.repeating_key_xor(&k_vec);
    let res_plain = String::from_utf8(res).unwrap();
    assert!(res_plain.contains("I'm rated"));
}
```

Il test dimostra un attacco completo e automatizzato: nessun intervento manuale, solo primitivi statistici applicati sistematicamente al corpus di ciphertext.

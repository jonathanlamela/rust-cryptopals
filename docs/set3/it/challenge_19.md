---
layout: default
title: "Sfida 19 — Rompi CTR con nonce fisso (statisticamente)"
parent: "Set 3 — IT"
nav_order: 3
permalink: /set3/it/challenge_19/
lang: it
---

# Sfida 19 — Rompi CTR con nonce fisso (statisticamente)

[← Sfida precedente](../challenge_18/) · [Sfida successiva →](../challenge_20/) · [🇬🇧 English](../../en/challenge_19/) · [Indice Set 3](../)

---

## Teoria

Quando la modalità CTR viene usata con lo stesso nonce per cifrare messaggi multipli, tutti i messaggi condividono lo stesso keystream. Questo equivale esattamente al riutilizzo di un one-time pad: se si hanno `C1 = P1 XOR K` e `C2 = P2 XOR K`, allora `C1 XOR C2 = P1 XOR P2`. Se P1 e P2 sono testi in linguaggio naturale, la distribuzione di frequenza di `P1 XOR P2` rivela informazioni su entrambi.

La sfida 19 introduce questo attacco in forma "manuale": il file `data_19.txt` contiene testi in Base64, ognuno cifrato con lo stesso keystream (nonce = 0, stessa chiave casuale). Il test cifra tutti i testi e li raccoglie in un vettore di ciphertext.

L'attacco statistico funziona così: si allineano tutti i ciphertext e si guarda ogni "colonna" (i byte alla posizione i di ogni ciphertext). Tutti questi byte sono stati XORati con lo stesso byte di keystream `K[i]`. Questo è esattamente il problema della sfida 3 (XOR a singolo byte): si applica `evaluate_frequency` per trovare il byte di chiave più probabile per ogni posizione.

Il risultato non è perfetto (soprattutto per le posizioni finali dove ci sono pochi ciphertext sufficientemente lunghi), ma rivela la maggior parte del keystream e permette di leggere la maggior parte dei plaintext.

## Concetti chiave

- **Nonce fisso:** stesso nonce → stesso keystream → many-time pad vulnerability.
- **Many-time pad attack:** dati K ciphertext con stesso keystream, si applica analisi frequenziale su ogni colonna.
- **`nonce_ctr_encrypt` con nonce zero:** `vec![0; 8]` come nonce per tutti i messaggi.
- **Analisi colonnare:** raggruppa i byte alla stessa posizione da tutti i ciphertext.
- **`data_19.txt`:** file con testi di poesia (W.B. Yeats) in Base64.
- **Limitazione:** l'attacco funziona solo per le posizioni con abbastanza ciphertext di lunghezza sufficiente.

## Spiegazione del codice

### Struttura generale

Il test in `src/set3.rs` legge il file, cifra ogni riga con `nonce_ctr_encrypt` e nonce zero, raccoglie i risultati. La verifica è minima (controlla solo che ci siano risultati), poiché il vero attacco richiede analisi manuale.

### Implementazione

La cifratura di tutti i testi con lo stesso nonce:

```rust
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
```

`vec![0; 8]` è il nonce di 8 byte tutto zero. La stessa `key` generata casualmente viene usata per tutti i messaggi. `nonce_ctr_encrypt` cifra ogni messaggio con nonce=0 e contatore incrementale — il keystream è identico per tutti.

L'attacco (non mostrato esplicitamente nel test, ma implicito nel commento) richiederebbe:

```rust
// Pseudo-codice dell'attacco
for i in 0..min_length {
    let column: Vec<u8> = results.iter().map(|c| c[i]).collect();
    if let Some((_, key_byte, _)) = column.evaluate_frequency() {
        keystream.push(key_byte);
    }
}
```

### Il test

```rust
#[test]
pub fn challenge_19() {
    const BLOCK_SIZE: usize = 16;
    let key = BLOCK_SIZE.random_block();
    let file_path = "./data/data_19.txt";
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
    assert!(results.len() != 0);
}
```

Il test verifica solo che siano stati prodotti ciphertext — la vulnerabilità è dimostrata dal fatto che tutti condividono lo stesso keystream, evidenziata nella sfida 20 con un attacco automatico completo.

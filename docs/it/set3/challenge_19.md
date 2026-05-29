---
layout: default
title: "Sfida 19 — Rompi CTR a nonce fisso (sostituzione)"
parent: "Set 3 IT"
grand_parent: IT
nav_order: 3
permalink: /it/set3/challenge_19/
lang: it
---

# Sfida 19 — Rompi CTR a nonce fisso (sostituzione)

[← Sfida precedente](../challenge_18/) · [Sfida successiva →](../challenge_20/) · [🇬🇧 English](../../../en/set3/challenge_19/) · [Set 3](../) · [Home](../../)

---

## Teoria

Quando più messaggi sono cifrati con la stessa chiave CTR e lo stesso nonce, il keystream è identico per tutti. Questo significa che `C[i] = P[i] XOR K` per ogni messaggio `i`, dove `K` è il keystream fisso. Di conseguenza, `C[i] XOR C[j] = P[i] XOR P[j]`: lo XOR di due cifrati è lo XOR dei due testi in chiaro.

Questo è esattamente lo stesso problema dello XOR a chiave ripetuta della sfida 6, ma applicato a più messaggi invece di un singolo lungo messaggio. Un attaccante che osserva molti messaggi cifrati con lo stesso keystream può applicare tecniche statistiche per recuperare il keystream.

L'approccio manuale (sfida 19) consiste nel cercare sostituzioni: se si ipotizza che una certa posizione nel keystream abbia valore `k`, allora tutti i byte alla stessa posizione nei vari messaggi devono essere `P[i][pos] = C[i][pos] XOR k`. Se l'ipotesi di `k` è corretta, i byte decifrati devono sembrare caratteri inglesi plausibili. Questo è un lavoro in parte manuale, basato sull'intuizione linguistica.

La sfida 19 mostra che CTR con nonce fisso degenera in XOR a chiave ripetuta — la stessa vulnerabilità che abbiamo già imparato a sfruttare.

## Concetti chiave

- **Nonce fisso**: uso dello stesso nonce per più messaggi CTR, che produce lo stesso keystream.
- **Many-time pad**: uso di un keystream una sola volta per più messaggi, il grave errore equivalente al two-time pad.
- **`nonce_ctr_encrypt`**: metodo usato per cifrare ogni messaggio con lo stesso nonce (vettore di zero a 8 byte).
- **Attacco per sostituzione**: ipotesi manuale dei valori del keystream basata sulla plausibilità linguistica.
- **Testo di Yeats**: i messaggi in chiaro sono versi di poesie di W.B. Yeats codificati in Base64 nel file `data_19.txt`.
- **Keystream condiviso**: elemento comune tra tutti i cifrati che permette di collegare i messaggi.

## Spiegazione del codice

### Struttura generale

La sfida usa `src/cryptovec/mod.rs` (`nonce_ctr_encrypt`) e legge i messaggi da `data/data_19.txt`. L'attacco non è automatizzato nel test: il test verifica solo che la cifratura sia stata eseguita su tutti i messaggi.

### Implementazione

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

Ogni riga del file è un messaggio Base64. Si decodifica in byte e si cifra con `nonce_ctr_encrypt` usando il nonce fisso `vec![0; 8]` (8 byte a zero). La chiave è casuale ma fissa per tutta la sessione. I risultati sono accumulati nel vettore `results`.

Poiché `nonce_ctr_encrypt` usa la funzione `nonce_count` con `write_u64::<LittleEndian>(count as u64)`, il nonce a 8 byte più il contatore a 8 byte in little-endian formano il blocco da 16 byte che viene cifrato con AES per produrre ogni pezzo di keystream.

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

Il test verifica solo che siano stati prodotti cifrati (il vettore `results` non è vuoto). L'analisi statistica dei cifrati per recuperare il keystream è lasciata come esercizio manuale.

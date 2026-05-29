---
layout: default
title: "Sfida 8 — Rileva AES in modalità ECB"
parent: "Set 1 — IT"
nav_order: 8
permalink: /set1/it/challenge_08/
lang: it
---

# Sfida 8 — Rileva AES in modalità ECB

[← Sfida precedente](../challenge_07/) · [🇬🇧 English](../../en/challenge_08/) · [Indice Set 1](../../)

---

## Teoria

La debolezza fondamentale della modalità ECB è che blocchi di plaintext identici producono blocchi di ciphertext identici, indipendentemente dalla loro posizione nel messaggio. Questo avviene perché ogni blocco viene cifrato in modo completamente indipendente, senza alcun feedback dagli altri blocchi.

Questa proprietà rende ECB rilevabile: se un ciphertext ECB contiene blocchi ripetuti, quasi certamente il plaintext corrispondente conteneva blocchi ripetuti nella stessa chiave. In pratica, qualsiasi dato strutturato — un database, un formato di file, dati con campi fissi — produce ciphertext ECB con blocchi ripetuti.

La tecnica di rilevamento è semplice: dividere il ciphertext in blocchi da 16 byte e cercare duplicati. Se esistono blocchi identici, il ciphertext è quasi certamente prodotto da ECB. Questa tecnica non rompe la cifratura (non recupera la chiave o il plaintext), ma permette di identificare quale modalità è stata usata — informazione preziosa per un attacco.

In Rust, il trait `CryptoVecChunks` definito in `src/cryptovec/mod.rs` fornisce il metodo `contains_duplicates` su `Vec<&[u8]>`. La ricerca di duplicati usa il classico algoritmo sort-dedup: si ordina il vettore, si rimuovono i duplicati, e se la lunghezza cambia significa che c'erano duplicati.

## Concetti chiave

- **Debolezza ECB:** blocchi di plaintext identici → blocchi di ciphertext identici.
- **Rilevamento di ECB:** cerca blocchi da 16 byte duplicati nel ciphertext.
- **`contains_duplicates`:** metodo che rileva duplicati ordinando e deduplicando un vettore.
- **`CryptoVecChunks`:** trait per operazioni su slice di chunk di byte.
- **Sort-dedup:** algoritmo O(n log n) per trovare duplicati tramite ordinamento.
- **Non è un attacco completo:** il rilevamento non recupera la chiave, solo identifica la modalità.

## Spiegazione del codice

### Struttura generale

Il trait `CryptoVecChunks` in `src/cryptovec/mod.rs` implementa `contains_duplicates` su `Vec<&[u8]>`. Il test in `src/set1.rs` legge righe da un file, divide ogni riga in chunk da 32 caratteri hex (= 16 byte), e verifica se ci sono duplicati.

### Implementazione

Il trait `CryptoVecChunks`:

```rust
pub trait CryptoVecChunks {
    fn contains_duplicates(&mut self) -> bool;
}

impl CryptoVecChunks for Vec<&[u8]> {
    fn contains_duplicates(&mut self) -> bool {
        let len = self.len();
        self.sort();
        self.dedup();
        len != self.len()
    }
}
```

`self.sort()` ordina le slice lessicograficamente — necessario affinché `dedup` funzioni (rimuove solo adiacenti uguali). `self.dedup()` rimuove gli elementi adiacenti duplicati. Se la lunghezza dopo `dedup` è diversa da quella originale, esistevano duplicati.

### Il test

```rust
#[test]
fn challenge_8() {
    let file_path = "./data/data_8.txt";
    let file = File::open(file_path).expect("Unable to read file");
    let buf_reader = BufReader::new(file);

    for line in buf_reader.lines() {
        if line.is_ok() {
            let unwrapped_line = line.unwrap();
            let line_bytes = unwrapped_line.as_bytes();
            let mut v_slices: Vec<&[u8]> = line_bytes.chunks(32).collect();
            if v_slices.contains_duplicates() {
                assert_eq!(unwrapped_line,
                    "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
                )
            }
        }
    }
}
```

Il file contiene stringhe hex una per riga. Il test divide ogni riga in chunk da 32 caratteri (ogni coppia di caratteri hex rappresenta un byte, quindi 32 caratteri = 16 byte = un blocco AES). La riga che contiene `08649af70dc06f4fd5d2d69c744cd283` ripetuto quattro volte è quella cifrata in ECB. Il test verifica che sia esattamente quella riga a essere rilevata.

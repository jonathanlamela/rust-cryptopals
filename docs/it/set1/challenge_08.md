---
layout: default
title: "Sfida 8 — Rileva AES ECB"
parent: "Set 1 IT"
grand_parent: IT
nav_order: 8
permalink: /it/set1/challenge_08/
lang: it
---

# Sfida 8 — Rileva AES ECB

[← Sfida precedente](../challenge_07/) · [🇬🇧 English](../../../en/set1/challenge_08/) · [Set 1](../) · [Home](../../)

---

## Teoria

Come discusso nella sfida 7, la modalità ECB ha una debolezza fondamentale: blocchi di testo in chiaro identici producono blocchi di testo cifrato identici quando cifrati con la stessa chiave. Questo permette di rilevare l'uso di ECB senza conoscere la chiave, semplicemente cercando blocchi duplicati nel testo cifrato.

In pratica, un file di testo cifrato contenente dati strutturati o ripetitivi (come record di database, campi di lunghezza fissa, immagini) è molto probabile che mostri blocchi duplicati se cifrato in ECB. Al contrario, per dati casuali o non strutturati, la probabilità che due blocchi da 16 byte siano identici per caso è trascurabile (1/2^128 per blocchi di testo in chiaro veramente casuali).

Il rilevamento di ECB è una delle prime tecniche di analisi del traffico cifrato usata dai ricercatori di sicurezza. Negli anni 2000, diverse implementazioni reali usavano ECB per cifrare cookie di sessione, token di autenticazione e altri dati strutturati. Poter rilevare ECB permetteva di capire la struttura del sistema anche senza decifrare i dati, e spesso era il primo passo verso attacchi più sofisticati come l'ECB cut-and-paste della sfida 13.

Il test prende 327 righe di testo hex, divide ogni riga in blocchi da 32 caratteri hex (= 16 byte), e cerca duplicati. Una sola riga ha blocchi duplicati: quella è stata cifrata in ECB.

## Concetti chiave

- **Rilevamento ECB**: identificazione di testo cifrato prodotto con ECB tramite ricerca di blocchi duplicati.
- **Dimensione del blocco AES**: 16 byte = 32 caratteri hex; unità di rilevamento per la ricerca di duplicati.
- **`contains_duplicates`**: metodo del trait `CryptoVecChunks` che verifica se un vettore di slice ha elementi duplicati.
- **Ordinamento e deduplicazione**: tecnica Rust che usa `sort` + `dedup` per trovare duplicati in O(n log n).
- **Analisi del traffico cifrato**: studio delle proprietà strutturali di testi cifrati senza conoscere la chiave.
- **Falso negativo**: rischio che testo cifrato in ECB non mostri duplicati se i blocchi di testo in chiaro corrispondenti sono tutti distinti.

## Spiegazione del codice

### Struttura generale

La sfida usa `src/cryptovec/mod.rs`, specificamente il trait `CryptoVecChunks` implementato su `Vec<&[u8]>` con il metodo `contains_duplicates`.

### Implementazione

Il metodo `contains_duplicates` usa un trucco efficiente:

```rust
impl CryptoVecChunks for Vec<&[u8]> {
    fn contains_duplicates(&mut self) -> bool {
        let len = self.len();
        self.sort();
        self.dedup();
        len != self.len()
    }
}
```

Prima salva la lunghezza originale, poi ordina il vettore (necessario perché `dedup` rimuove solo elementi adiacenti duplicati), poi chiama `dedup` per rimuovere i duplicati. Se la lunghezza dopo `dedup` è diversa da quella originale, c'erano duplicati. Questo è O(n log n) per il sort invece del naïve O(n²) del confronto a coppie.

Nel test, ogni riga del file viene divisa in chunk da 32 byte (caratteri hex, non byte binari) con `.chunks(32)`:

```rust
let mut v_slices: Vec<&[u8]> = line_bytes.chunks(32).collect();
if v_slices.contains_duplicates() {
    assert_eq!(unwrapped_line, "d880619740...");
}
```

Nota: il test lavora sui caratteri ASCII della rappresentazione hex, non sui byte decodificati. Questo è corretto perché due blocchi hex identici corrispondono a due blocchi cifrati identici.

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
                    "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a")
            }
        }
    }
}
```

Il test non ha un `assert` esplicito che fallisce se nessuna riga ha duplicati — quindi se il file fosse vuoto il test passerebbe silenziosamente. In pratica, la riga con blocchi duplicati è identificata e verificata contro il valore atteso.

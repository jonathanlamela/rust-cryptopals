---
layout: default
title: "Sfida 6 — Rompi XOR a chiave ripetuta"
parent: "Set 1 — IT"
nav_order: 6
permalink: /set1/it/challenge_06/
lang: it
---

# Sfida 6 — Rompi XOR a chiave ripetuta

[← Sfida precedente](../challenge_05/) · [Sfida successiva →](../challenge_07/) · [🇬🇧 English](../../en/challenge_06/) · [Indice Set 1](../../)

---

## Teoria

La rottura del cifrario XOR a chiave ripetuta è uno degli attacchi crittanalitici più eleganti della storia. Combina due idee: la distanza di Hamming per trovare la lunghezza della chiave, e l'analisi delle frequenze (sfida 3) applicata in parallelo su ogni "posizione di chiave".

La distanza di Hamming tra due sequenze di byte è il numero di bit che differiscono tra le due sequenze. Si calcola facendo XOR dei byte corrispondenti e contando i bit settati a 1 nel risultato (operazione `popcount`). Se la lunghezza di chiave ipotetica è corretta, blocchi di ciphertext distanti una lunghezza di chiave hanno una distanza di Hamming normalizzata bassa — perché i byte corrispondenti del plaintext (in inglese) sono statisticamente simili, e il XOR con la stessa chiave non aumenta la distanza.

Trovata la lunghezza della chiave K, si traspone il ciphertext: si prendono i byte alle posizioni 0, K, 2K, 3K,... (tutti XORati con lo stesso byte di chiave `key[0]`), poi i byte alle posizioni 1, K+1, 2K+1,... (tutti XORati con `key[1]`), e così via. Ogni colonna trasposta è un cifrario XOR a singolo byte, che si risolve con `evaluate_frequency` (sfida 3). Assemblando tutte le chiavi scoperte si ricostruisce la chiave completa.

Questo attacco è fondamentale nella storia della crittoanalisi moderna. Mostra che la semplice ripetizione di una chiave corta non è sufficiente a garantire la sicurezza, e gettò le basi per lo studio dei cifrari a flusso sicuri.

## Concetti chiave

- **Distanza di Hamming:** numero di bit che differiscono tra due sequenze di byte.
- **`popcount`:** conta i bit a 1 in un byte; `count_ones()` in Rust.
- **Lunghezza di chiave stimata:** il K che minimizza la distanza di Hamming normalizzata tra blocchi di ciphertext.
- **Trasposizione del ciphertext:** raggruppa i byte per posizione di chiave per ottenere cifrari monoalfabetici.
- **Attacco divide-et-impera:** decompone il problema in K istanze di sfida 3.
- **Normalizzazione per K:** la distanza di Hamming viene divisa per K per confrontare chiavi di diversa lunghezza.

## Spiegazione del codice

### Struttura generale

Il metodo `repeating_xor_attack` nel trait `CryptoVec` orchestra l'attacco: prima chiama `find_ks` per trovare la lunghezza di chiave migliore, poi traspone il ciphertext, poi chiama `evaluate_frequency` su ogni colonna.

### Implementazione

Il calcolo della distanza di Hamming:

```rust
fn compute_distance_bytes(&self, bytes_b: &Vec<u8>) -> u32 {
    self.iter()
        .zip(bytes_b.iter())
        .fold(0, |acc, (&byte_a, &byte_b)| {
            acc + (byte_a ^ byte_b).count_ones()
        })
}
```

`byte_a ^ byte_b` fa XOR dei byte: i bit diversi diventano 1. `.count_ones()` conta i bit a 1 — questa è la popcount. `.fold` accumula la somma.

Il metodo `find_ks` trova la lunghezza di chiave ottimale:

```rust
fn find_ks(&self) -> Result<usize, JlmCryptoErrors> {
    let mut out_keysize: Option<usize> = None;
    let mut out_dist = f64::INFINITY;
    for ks in 2..40 {
        let chunks: Vec<&[u8]> = self.chunks(ks).collect();
        let block1 = chunks.get(0).unwrap().to_vec();
        let block2 = chunks.get(1).unwrap().to_vec();
        let block3 = chunks.get(2).unwrap().to_vec();
        let block4 = chunks.get(3).unwrap().to_vec();
        let ds = (&block1.compute_distance_bytes(&block2)
            + &block1.compute_distance_bytes(&block3)
            + &block1.compute_distance_bytes(&block4)
            + &block2.compute_distance_bytes(&block3)
            + &block2.compute_distance_bytes(&block4)
            + &block3.compute_distance_bytes(&block4)) as f64
            / (6.0 * ks as f64);
        if out_keysize.is_some() {
            if ds < out_dist { out_dist = ds; out_keysize = Some(ks); }
        } else {
            out_dist = ds; out_keysize = Some(ks);
        }
    }
    if let Some(ks) = out_keysize { Ok(ks) } else { Err(JlmCryptoErrors::UnableFindKs) }
}
```

Per ogni lunghezza di chiave da 2 a 39, si calcolano le distanze di Hamming tra tutte le coppie dei primi 4 blocchi (6 coppie) e si media il tutto normalizzando per K. Il K con la distanza minima è il più probabile.

Il metodo `repeating_xor_attack` assembla l'attacco completo:

```rust
fn repeating_xor_attack(&self) -> Result<String, JlmCryptoErrors> {
    let ks = self.find_ks().unwrap();
    let mut transposed: Vec<Vec<u8>> = vec![vec![]; ks];
    for slice in self.chunks(ks) {
        let s_len = slice.len();
        if s_len == ks {
            for i in 0..s_len {
                transposed[i].push(slice[i]);
            }
        }
    }
    let mut k_vec: Vec<u8> = Vec::new();
    for bl in transposed {
        match bl.evaluate_frequency() {
            Some((_, key, _)) => k_vec.push(key),
            None => {}
        }
    }
    if k_vec.len() > 0 {
        let repeating_key_xor_result = self.repeating_key_xor(&k_vec);
        match &str::from_utf8(&repeating_key_xor_result) {
            Ok(v) => Ok(v.to_string()),
            Err(_) => Err(JlmCryptoErrors::BreakRepeatingKeyAttackFailed),
        }
    } else {
        Err(JlmCryptoErrors::BreakRepeatingKeyAttackFailed)
    }
}
```

Trasposizione: per ogni chunk di `ks` byte, l'i-esimo byte va nella i-esima colonna. Ogni colonna è poi attaccata con `evaluate_frequency`. La chiave risultante `k_vec` viene usata per decifrare il ciphertext originale con `repeating_key_xor`.

### Il test

```rust
#[test]
fn challenge_6() {
    let file_path = "./data/data_6.txt";
    let mut file = File::open(file_path).expect("Unable to read file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Error reading file.");
    let buffer_to_string = &str::from_utf8(&buffer).unwrap().replace("\n", "");
    let input: Base64 = Base64::from_string(buffer_to_string.to_string());
    match input.to_bytes() {
        Ok(bytes) => match bytes.repeating_xor_attack() {
            Ok(result) => { assert_eq!(result, YELLOW_SUBMARINE_STRING) }
            Err(_) => panic!("Test failed"),
        },
        Err(_) => { panic!("Invalid base64 to bytes") }
    }
}
```

Il file contiene il ciphertext in Base64. Le newline vengono rimosse prima della decodifica. Il plaintext atteso è la canzone "Play That Funky Music" di Vanilla Ice.

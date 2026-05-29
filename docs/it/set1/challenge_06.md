---
layout: default
title: "Sfida 6 — Rompi XOR a chiave ripetuta"
parent: "Set 1 IT"
grand_parent: IT
nav_order: 6
permalink: /it/set1/challenge_06/
lang: it
---

# Sfida 6 — Rompi XOR a chiave ripetuta

[← Sfida precedente](../challenge_05/) · [Sfida successiva →](../challenge_07/) · [🇬🇧 English](../../../en/set1/challenge_06/) · [Set 1](../) · [Home](../../)

---

## Teoria

L'attacco al cifrario di Vigenère (XOR a chiave ripetuta) è uno dei più eleganti della crittografia classica. Si compone di due fasi distinte: prima trovare la lunghezza della chiave, poi rompere ogni sotto-cifrario a byte singolo separatamente.

La prima fase sfrutta la distanza di Hamming, anche chiamata distanza di editing a livello di bit. La distanza di Hamming tra due stringhe di bit è il numero di posizioni in cui differiscono. Per due blocchi di testo in chiaro casuali, la distanza di Hamming normalizzata per la lunghezza del blocco è vicina a 4 (in media, metà dei bit differiscono). Tuttavia, se si prendono due blocchi consecutivi di un cifrato e si calcola la loro distanza di Hamming, quando la lunghezza del blocco è uguale alla lunghezza della chiave, i due blocchi sono stati cifrati con la stessa chiave, quindi la distanza di Hamming riflette solo la distanza tra i due blocchi di testo in chiaro — che è molto più bassa per testo naturale. Cercando la lunghezza di blocco che minimizza la distanza di Hamming normalizzata, si trova la lunghezza della chiave.

La seconda fase è la trasposizione: una volta nota la lunghezza della chiave K, si costruisce K "colonne" prendendo i byte alle posizioni 0, K, 2K, ... per la prima colonna; i byte alle posizioni 1, K+1, 2K+1, ... per la seconda; e così via. Ogni colonna è un cifrario XOR a byte singolo, e si può attaccare con l'analisi della frequenza come nella sfida 3. La chiave completa si ottiene combinando i byte di chiave trovati per ogni colonna.

## Concetti chiave

- **Distanza di Hamming**: numero di bit in cui due stringhe differiscono; misura la dissimilarità bit a bit.
- **Normalizzazione**: dividere la distanza di Hamming per la lunghezza del blocco per rendere comparabili blocchi di lunghezze diverse.
- **Trasposizione**: riorganizzazione del cifrato in colonne, ognuna delle quali è un single-byte XOR.
- **`find_ks`**: metodo di `CryptoVec` che trova la lunghezza della chiave minimizzando la distanza di Hamming normalizzata.
- **`compute_distance_bytes`**: metodo di `CryptoVec` che calcola la distanza di Hamming tra due vettori.
- **`repeating_xor_attack`**: metodo di `CryptoVec` che orchestra l'intero attacco: trova la chiave e decifra il testo.

## Spiegazione del codice

### Struttura generale

La sfida usa interamente `src/cryptovec/mod.rs`. I metodi principali sono `repeating_xor_attack`, `find_ks`, `compute_distance_bytes` e `evaluate_frequency`.

### Implementazione

`compute_distance_bytes` calcola la distanza di Hamming:

```rust
fn compute_distance_bytes(&self, bytes_b: &Vec<u8>) -> u32 {
    self.iter()
        .zip(bytes_b.iter())
        .fold(0, |acc, (&byte_a, &byte_b)| {
            acc + (byte_a ^ byte_b).count_ones()
        })
}
```

XOR di due byte produce un valore dove ogni bit a 1 indica una differenza. `count_ones()` conta i bit a 1 in un `u8`, fornendo il numero di posizioni in cui i due byte differiscono. L'accumulo su tutti i byte produce la distanza totale.

`find_ks` cerca la lunghezza della chiave:

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
            if ds < out_dist {
                out_dist = ds;
                out_keysize = Some(ks);
            }
        } else {
            out_dist = ds;
            out_keysize = Some(ks);
        }
    }
    if let Some(ks) = out_keysize {
        Ok(ks)
    } else {
        Err(JlmCryptoErrors::UnableFindKs)
    }
}
```

Per ogni lunghezza candidata da 2 a 39, prende i primi quattro blocchi e calcola la media delle sei distanze di Hamming normalizzate. L'uso di sei coppie invece di due riduce la varianza della stima.

`repeating_xor_attack` orchestra l'attacco completo: trova `ks`, traspone i dati in colonne, attacca ogni colonna con `evaluate_frequency`, assembla la chiave, e decifra il testo:

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
        let result = self.repeating_key_xor(&k_vec);
        match &str::from_utf8(&result) {
            Ok(v) => Ok(v.to_string()),
            Err(_) => Err(JlmCryptoErrors::BreakRepeatingKeyAttackFailed),
        }
    } else {
        Err(JlmCryptoErrors::BreakRepeatingKeyAttackFailed)
    }
}
```

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
            Ok(result) => assert_eq!(result, YELLOW_SUBMARINE_STRING),
            Err(_) => panic!("Test failed"),
        },
        Err(_) => panic!("Invalid base64 to bytes"),
    }
}
```

Legge un file Base64, decodifica in byte e chiama `repeating_xor_attack`. Il risultato atteso è il testo completo di "Play That Funky Music" di Vanilla Ice.

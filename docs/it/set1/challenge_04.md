---
layout: default
title: "Sfida 4 — Rileva XOR a carattere singolo"
parent: "Set 1 IT"
grand_parent: IT
nav_order: 4
permalink: /it/set1/challenge_04/
lang: it
---

# Sfida 4 — Rileva XOR a carattere singolo

[← Sfida precedente](../challenge_03/) · [Sfida successiva →](../challenge_05/) · [🇬🇧 English](../../../en/set1/challenge_04/) · [Set 1](../) · [Home](../../)

---

## Teoria

La sfida 4 estende il problema della sfida 3 a un contesto multi-messaggio. Invece di decifrare un singolo cifrato, dobbiamo individuare quale tra le 327 righe di un file è stata cifrata con XOR a byte singolo, e poi decifrarne il contenuto. Questo è un problema di detection prima che di decryption.

In scenari reali, un analista potrebbe dover esaminare grandi quantità di traffico di rete per individuare messaggi sospetti. La capacità di distinguere automaticamente dati cifrati da dati casuali o non cifrati è un'abilità fondamentale. Un testo cifrato con XOR a byte singolo ha una distribuzione delle frequenze dei byte molto particolare: i byte ad alta frequenza nel testo in chiaro rimangono ad alta frequenza nel cifrato (solo con valori diversi), mentre i byte a bassa frequenza rimangono rari.

L'approccio consiste nel applicare l'algoritmo di analisi della frequenza della sfida 3 a ogni riga del file, raccogliere tutti i risultati validi (le righe per cui è stato possibile trovare una chiave plausibile), e poi selezionare il risultato globalmente migliore: quello con il punteggio più alto tra tutti. Il punteggio è naturalmente il logaritmo della somma delle frequenze delle lettere nel testo decifrato.

La minima variante rispetto alla sfida 3 è il modo in cui si cerca il massimo: per la sfida 3 il massimo è cercato con `max_by`, qui il codice usa invece `min_by` invertendo l'ordinamento per trovare il massimo punteggio (il codice usa la tupla con il punteggio come primo elemento e ordina inversamente, oppure il punteggio ha segno negativo — occorre leggere il codice con attenzione).

## Concetti chiave

- **Rilevamento di testo cifrato**: capacità di distinguere automaticamente quale sequenza di byte è probabilmente il risultato di una cifratura XOR.
- **Analisi multi-messaggio**: applicazione di un attacco su un insieme di messaggi per trovare quello vulnerabile.
- **Punteggio comparativo**: confronto tra i migliori risultati di decifrazione di ogni riga per trovare il vincitore globale.
- **`BufReader`**: struttura Rust per la lettura efficiente riga per riga di file di testo.
- **`Vec<(f64, String, Vec<u8>)>`**: tipo usato per raccogliere i risultati intermedi: punteggio, riga originale, testo decifrato.
- **Iteratori funzionali**: uso di `min_by` con `partial_cmp` per trovare l'elemento ottimale in una collezione.

## Spiegazione del codice

### Struttura generale

La sfida usa `src/set1.rs` per la logica di test, `src/hex/mod.rs` per il parsing hex, e `src/cryptovec/mod.rs` per `evaluate_frequency`. La lettura del file usa la libreria standard Rust con `BufReader`.

### Implementazione

Il test legge il file riga per riga e per ogni riga applica l'analisi della frequenza:

```rust
for line in buf_reader.lines() {
    if line.is_ok() {
        let unwrapped_line = line.unwrap();
        let hex_value = Hex::from_string(unwrapped_line.clone())
            .unwrap_or_else(|_| panic!("Conversion from Hex to byte failed"));
        let bytes = hex_value.to_bytes().unwrap_or_else(|_| {
            panic!("Conversion from Hex to byte failed");
        });
        match bytes.evaluate_frequency() {
            Some(result) => {
                readed_lines.push((result.0, unwrapped_line, result.2));
            }
            None => {}
        };
    }
}
```

Per ogni riga valida, `evaluate_frequency` restituisce `Some((punteggio, chiave, testo))` se esiste almeno un byte di chiave che produce un testo plausibile, oppure `None` se nessuna chiave produce un testo con caratteri ASCII validi. Solo le righe con un risultato `Some` vengono aggiunte al vettore `readed_lines`.

Dopo aver processato tutte le righe, si trova il risultato con punteggio migliore:

```rust
let value = readed_lines
    .iter()
    .min_by(|(a, _, _), (b, _, _)| b.partial_cmp(a).unwrap());
```

Il codice usa `min_by` con l'ordinamento invertito (`b.partial_cmp(a)` invece di `a.partial_cmp(b)`) per trovare il massimo del punteggio, che è la riga il cui miglior testo decifrato ha il punteggio linguistico più alto.

### Il test

```rust
#[test]
fn challenge_4() {
    let file_path = "./data/data_4.txt";
    let file = File::open(file_path).expect("Unable to read file");
    let buf_reader = BufReader::new(file);
    let mut readed_lines: Vec<(f64, String, Vec<u8>)> = Vec::new();
    // ... (loop sopra) ...
    if readed_lines.len() > 0 {
        let value = readed_lines
            .iter()
            .min_by(|(a, _, _), (b, _, _)| b.partial_cmp(a).unwrap());
        let value_unwrapped = value.unwrap();
        let stringa = str::from_utf8(&value_unwrapped.2).unwrap();
        assert_eq!(stringa, "Now that the party is jumping\n")
    } else {
        panic!("Test failed: No valid results found");
    }
}
```

Il testo atteso è "Now that the party is jumping\n", con il newline finale che fa parte del testo originale.

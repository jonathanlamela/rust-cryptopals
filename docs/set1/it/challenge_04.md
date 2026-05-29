---
layout: default
title: "Sfida 4 — Rileva XOR a carattere singolo"
parent: "Set 1 — IT"
nav_order: 4
permalink: /set1/it/challenge_04/
lang: it
---

# Sfida 4 — Rileva XOR a carattere singolo

[← Sfida precedente](../challenge_03/) · [Sfida successiva →](../challenge_05/) · [🇬🇧 English](../../en/challenge_04/) · [Indice Set 1](../../)

---

## Teoria

La sfida 4 è una generalizzazione della sfida 3: invece di avere una singola stringa cifrata da decifrare, si dispone di un file contenente centinaia di righe, ognuna delle quali è una stringa hex. Una sola di queste righe è stata cifrata con XOR a singolo byte; le altre sono dati casuali o non pertinenti. Il compito è identificare la riga cifrata e recuperarne il plaintext.

Questo scenario riflette un problema reale di intelligence e analisi forense: dato un corpus di dati potenzialmente enorme, trovare le porzioni che contengono informazioni cifrate. La tecnica si basa sulla stessa analisi delle frequenze della sfida 3, ma applicata in parallelo su molte righe. La riga che produce il plaintext con lo score di frequenza più alto è quella cifrata.

Dal punto di vista della progettazione software, questo problema introduce la necessità di gestire flussi di dati in ingresso (file IO), iterare su collezioni in modo efficiente, e aggregare risultati parziali. In Rust, il tipo `BufReader` permette di leggere un file riga per riga senza caricare tutto in memoria, e `Vec<(f64, String, Vec<u8>)>` aggrega i risultati intermedi.

Un aspetto importante è la gestione dei fallimenti: non tutte le righe del file sono stringhe hex valide, e non tutte le stringhe hex decodificano in testo ASCII plausibile. Il codice gestisce questi casi gracefully usando `match` e `Option`, saltando le righe problematiche senza abortire l'esecuzione.

La metrica di confronto finale è la stessa dello score di frequenza: si cerca il minimo della funzione di costo (negativo dello score massimo) oppure il massimo dello score positivo. Il codice usa `min_by` con ordinamento inverso, equivalente a cercare il massimo.

## Concetti chiave

- **Corpus di ciphertext:** insieme di molte stringhe, solo una delle quali è cifrata.
- **`BufReader`:** tipo Rust per lettura bufferizzata riga per riga da un file.
- **Aggregazione dei risultati:** raccogliere i migliori candidati da ogni riga e scegliere il migliore globale.
- **`partial_cmp`:** confronto per `f64` che gestisce i valori speciali (NaN, infinito).
- **Filtraggio lazy con `match`:** saltare le righe che non producono risultati validi.
- **Invariante di ordinamento:** `min_by` con confronto invertito equivale a `max_by`.

## Spiegazione del codice

### Struttura generale

Il test legge il file `./data/data_4.txt` riga per riga usando `BufReader`. Per ogni riga, crea un `Hex`, lo converte in byte e chiama `evaluate_frequency`. I risultati validi vengono raccolti in un `Vec`. Alla fine si trova il risultato con lo score più alto.

### Implementazione

La lettura del file:

```rust
let file = File::open(file_path).expect("Unable to read file");
let buf_reader = BufReader::new(file);
let mut readed_lines: Vec<(f64, String, Vec<u8>)> = Vec::new();
```

`File::open` apre il file. `BufReader::new` aggiunge bufferizzazione per una lettura riga per riga efficiente. Il vettore `readed_lines` accumula le triple `(score, riga_originale, plaintext)`.

Il ciclo di analisi:

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

`buf_reader.lines()` è un iteratore che produce `Result<String>`. Il controllo `if line.is_ok()` salta le righe con errori di IO. `evaluate_frequency()` restituisce `Option`, quindi `match` gestisce sia il caso `Some` (riga analizzata con successo) sia `None` (riga non plausibile come testo inglese).

La selezione del migliore:

```rust
let value = readed_lines
    .iter()
    .min_by(|(a, _, _), (b, _, _)| b.partial_cmp(a).unwrap());
```

`min_by` con comparatore `b.partial_cmp(a)` (invertito rispetto al normale) trova l'elemento con score più alto — è equivalente a `max_by`. `partial_cmp` è necessario perché `f64` non implementa `Ord` (a causa di NaN).

### Il test

```rust
#[test]
fn challenge_4() {
    let file_path = "./data/data_4.txt";
    let file = File::open(file_path).expect("Unable to read file");
    let buf_reader = BufReader::new(file);
    let mut readed_lines: Vec<(f64, String, Vec<u8>)> = Vec::new();

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

Il testo atteso è "Now that the party is jumping\n", incluso il newline finale. La riga trovata nel file produce questo plaintext quando decifrata con la chiave corretta.

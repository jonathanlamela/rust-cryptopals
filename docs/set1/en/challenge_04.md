---
layout: default
title: "Challenge 4 — Detect single-character XOR"
parent: "Set 1 — EN"
nav_order: 4
permalink: /set1/en/challenge_04/
lang: en
---

# Challenge 4 — Detect single-character XOR

[← Previous](../challenge_03/) · [Next →](../challenge_05/) · [🇮🇹 Italiano](../../it/challenge_04/) · [Set 1 index](../../)

---

## Theory

Challenge 4 generalises challenge 3: instead of a single encrypted string to decrypt, a file containing hundreds of lines is provided, each of which is a hex string. Only one of these lines was encrypted with single-byte XOR; the others are random or irrelevant data. The task is to identify the encrypted line and recover its plaintext.

This scenario reflects a real intelligence and forensic analysis problem: given a potentially enormous corpus of data, find the portions containing encrypted information. The technique is based on the same frequency analysis as challenge 3, but applied in parallel across many lines. The line that produces the plaintext with the highest frequency score is the encrypted one.

From a software design perspective, this problem introduces the need to handle input data streams (file IO), iterate over collections efficiently, and aggregate partial results. In Rust, `BufReader` allows reading a file line by line without loading everything into memory, and `Vec<(f64, String, Vec<u8>)>` aggregates intermediate results.

An important aspect is failure handling: not all lines in the file are valid hex strings, and not all hex strings decode into plausible ASCII text. The code handles these cases gracefully using `match` and `Option`, skipping problematic lines without aborting execution.

The final comparison metric is the same frequency score: we look for the minimum of the cost function (negative of the maximum score) or equivalently the maximum positive score. The code uses `min_by` with reversed ordering, equivalent to finding the maximum.

## Key concepts

- **Ciphertext corpus:** a collection of many strings, only one of which is encrypted.
- **`BufReader`:** Rust type for buffered line-by-line reading from a file.
- **Result aggregation:** collect best candidates from each line and choose the global best.
- **`partial_cmp`:** comparison for `f64` that handles special values (NaN, infinity).
- **Lazy filtering with `match`:** skip lines that do not produce valid results.
- **Ordering invariant:** `min_by` with reversed comparator is equivalent to `max_by`.

## Code walkthrough

### Overview

The test reads `./data/data_4.txt` line by line using `BufReader`. For each line it creates a `Hex`, converts it to bytes, and calls `evaluate_frequency`. Valid results are collected in a `Vec`. At the end the result with the highest score is selected.

### Implementation

File reading setup:

```rust
let file = File::open(file_path).expect("Unable to read file");
let buf_reader = BufReader::new(file);
let mut readed_lines: Vec<(f64, String, Vec<u8>)> = Vec::new();
```

`File::open` opens the file. `BufReader::new` adds buffering for efficient line-by-line reading. The `readed_lines` vector accumulates triples `(score, original_line, plaintext)`.

The analysis loop:

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

`buf_reader.lines()` is an iterator producing `Result<String>`. The `if line.is_ok()` check skips lines with IO errors. `evaluate_frequency()` returns `Option`, so `match` handles both the `Some` case (line successfully analysed) and `None` (line not plausible as English text).

Best candidate selection:

```rust
let value = readed_lines
    .iter()
    .min_by(|(a, _, _), (b, _, _)| b.partial_cmp(a).unwrap());
```

`min_by` with comparator `b.partial_cmp(a)` (reversed from normal) finds the element with the highest score — equivalent to `max_by`. `partial_cmp` is required because `f64` does not implement `Ord` (due to NaN).

### The test

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

The expected text is "Now that the party is jumping\n", including the trailing newline. The line found in the file produces this plaintext when decrypted with the correct key.

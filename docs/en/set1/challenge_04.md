---
layout: default
title: "Challenge 4 — Detect single-character XOR"
parent: "Set 1 EN"
grand_parent: EN
nav_order: 4
permalink: /en/set1/challenge_04/
lang: en
---

# Challenge 4 — Detect single-character XOR

[← Previous](../challenge_03/) · [Next →](../challenge_05/) · [🇮🇹 Italiano](../../../it/set1/challenge_04/) · [Set 1](../) · [Home](../../)

---

## Theory

Challenge 4 extends the problem of challenge 3 to a multi-message context. Instead of decrypting a single ciphertext, we must identify which one of 327 lines in a file was encrypted with single-byte XOR, and then decrypt its content. This is a detection problem before it is a decryption problem.

In real-world scenarios, an analyst might need to examine large amounts of network traffic to identify suspicious messages. The ability to automatically distinguish encrypted data from random or unencrypted data is a fundamental skill. A text encrypted with single-byte XOR has a very particular byte frequency distribution: the high-frequency bytes in the plaintext remain high-frequency in the ciphertext (just with different values), while low-frequency bytes remain rare.

The approach consists of applying the frequency analysis algorithm from challenge 3 to each line of the file, collecting all valid results (lines for which a plausible key was found), and then selecting the globally best result: the one with the highest score among all lines. The score is naturally the logarithm of the sum of letter frequencies in the decrypted text.

The slight variant with respect to challenge 3 is how the maximum is searched: the code uses `min_by` with reversed ordering to find the maximum score (the tuple has score as first element and is ordered inversely).

## Key concepts

- **Ciphertext detection**: ability to automatically distinguish which byte sequence is likely the result of XOR encryption.
- **Multi-message analysis**: applying an attack across a set of messages to find the vulnerable one.
- **Comparative scoring**: comparing the best decryption results of each line to find the global winner.
- **`BufReader`**: Rust structure for efficient line-by-line reading of text files.
- **`Vec<(f64, String, Vec<u8>)>`**: type used to collect intermediate results: score, original line, decrypted text.
- **Functional iterators**: use of `min_by` with `partial_cmp` to find the optimal element in a collection.

## Code walkthrough

### Overview

The challenge uses `src/set1.rs` for test logic, `src/hex/mod.rs` for hex parsing, and `src/cryptovec/mod.rs` for `evaluate_frequency`. File reading uses the Rust standard library with `BufReader`.

### Implementation

The test reads the file line by line and applies frequency analysis to each line:

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

For each valid line, `evaluate_frequency` returns `Some((score, key, text))` if at least one key byte produces a plausible text, or `None` if no key produces a text with valid ASCII characters. Only lines with a `Some` result are added to `readed_lines`.

After processing all lines, the result with the best score is found:

```rust
let value = readed_lines
    .iter()
    .min_by(|(a, _, _), (b, _, _)| b.partial_cmp(a).unwrap());
```

The code uses `min_by` with reversed ordering (`b.partial_cmp(a)` instead of `a.partial_cmp(b)`) to find the maximum score.

### The test

```rust
#[test]
fn challenge_4() {
    // ...
    let stringa = str::from_utf8(&value_unwrapped.2).unwrap();
    assert_eq!(stringa, "Now that the party is jumping\n")
}
```

The expected text is "Now that the party is jumping\n", including the trailing newline that is part of the original text.

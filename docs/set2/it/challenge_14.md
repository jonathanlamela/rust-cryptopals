---
layout: default
title: "Sfida 14 — Byte-at-a-time ECB decryption (difficile)"
parent: "Set 2 — IT"
nav_order: 6
permalink: /set2/it/challenge_14/
lang: it
---

# Sfida 14 — Byte-at-a-time ECB decryption (difficile)

[← Sfida precedente](../challenge_13/) · [Sfida successiva →](../challenge_15/) · [🇬🇧 English](../../en/challenge_14/) · [Indice Set 2](../../)

---

## Teoria

La sfida 14 è una versione più difficile della sfida 12: l'oracle aggiunge un prefisso casuale (di lunghezza sconosciuta tra 1 e 10 byte) oltre al suffisso segreto. Il prefisso è fisso per tutta la durata dell'attacco (non cambia tra le chiamate), ma la sua lunghezza e il suo contenuto sono ignoti.

La difficoltà aggiuntiva sta nel fatto che il prefisso "sposta" il confine tra il contenuto controllato e il suffisso segreto. Prima di applicare l'attacco byte-at-a-time, è necessario determinare la lunghezza del prefisso e aggiungere abbastanza byte di riempimento per allineare il contenuto controllato a un confine di blocco. Una volta fatto questo, l'attacco procede esattamente come nella sfida 12.

La determinazione della lunghezza del prefisso avviene in due fasi: prima si trova il numero di blocchi completi occupati dal prefisso (`prefix_blocks_count`), poi si determina esattamente quanti byte del prefisso sono nell'ultimo blocco parziale (`prefix_length`). Quest'ultima informazione si ottiene incrementalmente: si cifra un numero crescente di byte identici fino a quando il blocco target non cambia più — il momento in cui cambia indica che il prefisso è stato "riempito" al confine del blocco.

## Concetti chiave

- **Prefisso casuale a lunghezza sconosciuta:** complica l'allineamento dei blocchi rispetto alla sfida 12.
- **`prefix_length`:** determina quanti byte del prefisso occupano il blocco parziale.
- **`prefix_fill_len`:** numero di byte da aggiungere per allineare l'input al confine del blocco dopo il prefisso.
- **`chunks_count`:** metodo del trait `USizeCrypt` che calcola `(n_blocchi, n_fill_byte)`.
- **Stabilità del prefisso:** il prefisso non cambia tra le chiamate, permettendo l'analisi iterativa.
- **`CustomCrypter14`:** oracle con prefisso casuale di lunghezza casuale (1–10 byte).

## Spiegazione del codice

### Struttura generale

`src/crypters/custom_crypter_14.rs` definisce `CustomCrypter14` con gli stessi metodi di attacco di `CustomCrypter12` ma con supporto per il prefisso variabile.

### Implementazione

`prefix_length` in `CustomCrypter14`:

```rust
pub fn prefix_length(&self) -> Result<usize, JlmCryptoErrors> {
    let offset = self.prefix_blocks_count().unwrap() * Self::BLOCK_SIZE;
    let constant_block = vec![0u8; 16];
    let initial = &self.base.encrypt(&constant_block).unwrap()[offset..(offset + Self::BLOCK_SIZE)];
    for i in 0..Self::BLOCK_SIZE {
        let cur = self.base.encrypt(&constant_block[i + 1..]).unwrap();
        if cur.len() < offset + Self::BLOCK_SIZE
            || initial != &cur[offset..(offset + Self::BLOCK_SIZE)]
        {
            return Ok(i);
        }
    }
    Ok(Self::BLOCK_SIZE)
}
```

Inizia con 16 byte di input (un blocco completo). Riduce progressivamente l'input di un byte alla volta dal fondo. Quando il blocco target cambia, il numero di byte rimossi indica quanti byte del prefisso erano nell'ultimo blocco.

`get_suffix` in `CustomCrypter14` ha la stessa logica di `CustomCrypter12`, ma usa `prefix_fill_len` per allineare correttamente l'input al confine del blocco dopo il prefisso.

Il trait `USizeCrypt::chunks_count`:

```rust
fn chunks_count(self) -> (usize, usize) {
    let q = (self + 16 - 1) / 16;
    let r = q * 16 - self;
    (q, r)
}
```

`q` è il numero di blocchi da 16 byte necessari per contenere `self` byte. `r` è il numero di byte di fill necessari per completare l'ultimo blocco.

### Il test

```rust
#[test]
pub fn challenge_14() {
    let oracle = CustomCrypter14::new();
    let base64_suffix = Base64::from_string(String::from(
        "Um9sbGluJyBpbiBteSA1LjAK..."
    ));
    match oracle {
        Ok(r) => {
            assert_eq!(base64_suffix, Base64::from_bytes(r.get_suffix().unwrap().as_slice()))
        }
        Err(_) => { panic!(); }
    }
}
```

Come nella sfida 12, il test verifica che il suffisso estratto corrisponda al valore atteso, anche in presenza del prefisso casuale.

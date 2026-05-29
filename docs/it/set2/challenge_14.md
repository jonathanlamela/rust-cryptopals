---
layout: default
title: "Sfida 14 — Byte-at-a-time ECB (difficile)"
parent: "Set 2 IT"
grand_parent: IT
nav_order: 6
permalink: /it/set2/challenge_14/
lang: it
---

# Sfida 14 — Byte-at-a-time ECB (difficile)

[← Sfida precedente](../challenge_13/) · [Sfida successiva →](../challenge_15/) · [🇬🇧 English](../../../en/set2/challenge_14/) · [Set 2](../) · [Home](../../)

---

## Teoria

La sfida 14 è una variante più difficile della sfida 12. La differenza è che l'oracolo aggiunge un prefisso casuale di lunghezza sconosciuta (1–10 byte) prima del testo controllato dall'attaccante. Questo prefisso è lo stesso per ogni chiamata all'oracolo ma la sua lunghezza è ignota.

Il problema aggiuntivo rispetto alla sfida 12 è che non sappiamo dove inizia il nostro testo controllato nello spazio dei blocchi. Dobbiamo prima determinare la lunghezza e la posizione del prefisso, poi compensare per allineare il nostro attacco.

L'approccio è il seguente: si trovano i blocchi "prefisso" confrontando i cifrati di due input che differiscono solo per un byte — i blocchi che differiscono tra i due cifrati sono quelli influenzati dal nostro input. Il numero di blocchi prima del primo blocco che differisce è il numero di blocchi completi del prefisso. La lunghezza esatta del prefisso nel blocco parziale si determina aggiungendo uno a uno byte di filler finché il blocco non si stabilizza (uguale a un cifrario con un byte in meno nel blocco target).

Una volta nota la lunghezza del prefisso, si aggiunge il filler necessario per allineare il prefisso a un confine di blocco, e poi si applica l'attacco byte-at-a-time come nella sfida 12.

## Concetti chiave

- **Prefisso ignoto**: lunghezza del prefisso dell'oracolo sconosciuta ma fissa per ogni istanza.
- **`prefix_blocks_count`**: metodo che trova quanti blocchi completi occupa il prefisso.
- **`prefix_length`**: metodo che trova la lunghezza esatta del prefisso.
- **`prefix_plus_suffix_length`**: metodo che calcola la lunghezza totale di prefisso + suffisso.
- **Padding di allineamento**: byte aggiunti dall'attaccante per portare il prefisso a un confine di blocco.
- **`CustomCrypter14`**: oracolo con prefisso casuale di lunghezza 1–10 byte oltre al suffisso fisso.

## Spiegazione del codice

### Struttura generale

La sfida usa `src/crypters/custom_crypter_14.rs`. La logica è analoga a `CustomCrypter12` ma con l'aggiunta della gestione del prefisso casuale.

### Implementazione

`prefix_blocks_count` trova il numero di blocchi completi del prefisso:

```rust
pub fn prefix_blocks_count(&self) -> Result<usize, JlmCryptoErrors> {
    let encrypted_0 = self.base.encrypt(&[0]).unwrap();
    let encrypted_1 = self.base.encrypt(&[1]).unwrap();
    let chunks_0 = encrypted_0.chunks(Self::BLOCK_SIZE);
    let chunks_1 = encrypted_1.chunks(Self::BLOCK_SIZE);
    if let Some(result) = chunks_0.zip(chunks_1).position(|(x, y)| x != y) {
        Ok(result)
    } else {
        Err(JlmCryptoErrors::NoDifferentBlocks)
    }
}
```

Confronta i cifrati di input `[0]` e `[1]` blocco per blocco. Il primo blocco che differisce è quello che contiene il nostro byte di input, quindi tutti i blocchi prima di esso sono interamente prefisso.

`prefix_length` raffina il calcolo trovando l'esatto numero di byte del prefisso nell'ultimo blocco parziale:

```rust
pub fn prefix_length(&self) -> Result<usize, JlmCryptoErrors> {
    let offset = self.prefix_blocks_count().unwrap() * Self::BLOCK_SIZE;
    let constant_block = vec![0u8; Self::BLOCK_SIZE];
    let initial = &self.base.encrypt(&constant_block).unwrap()[offset..(offset + Self::BLOCK_SIZE)];
    for i in 0..Self::BLOCK_SIZE {
        let cur = self.base.encrypt(&constant_block[i + 1..]).unwrap();
        if cur.len() < offset + Self::BLOCK_SIZE || initial != &cur[offset..(offset + Self::BLOCK_SIZE)] {
            return Ok(i);
        }
    }
    Ok(Self::BLOCK_SIZE)
}
```

Riduce progressivamente il block costante: quando il blocco all'offset cambia, significa che i byte del nostro input non riempiono più il blocco parziale del prefisso, quindi la lunghezza del prefisso in quel blocco è `i`.

### Il test

```rust
#[test]
pub fn challenge_14() {
    let oracle = CustomCrypter14::new();
    let base64_suffix = Base64::from_string(String::from("Um9sbGluJyBpbiBteSA1LjAK..."));
    match oracle {
        Ok(r) => {
            assert_eq!(base64_suffix, Base64::from_bytes(r.get_suffix().unwrap().as_slice()))
        }
        Err(_) => panic!(),
    }
}
```

Verifica che il suffisso recuperato (con prefisso casuale) corrisponda al suffisso Base64 noto.

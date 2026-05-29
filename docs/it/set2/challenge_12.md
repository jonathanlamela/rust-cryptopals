---
layout: default
title: "Sfida 12 — Byte-at-a-time ECB (semplice)"
parent: "Set 2 IT"
grand_parent: IT
nav_order: 4
permalink: /it/set2/challenge_12/
lang: it
---

# Sfida 12 — Byte-at-a-time ECB (semplice)

[← Sfida precedente](../challenge_11/) · [Sfida successiva →](../challenge_13/) · [🇬🇧 English](../../../en/set2/challenge_12/) · [Set 2](../) · [Home](../../)

---

## Teoria

L'attacco "byte-at-a-time" è uno degli attacchi più eleganti contro gli oracoli ECB. L'oracolo cifra in ECB `prefisso_controllato || suffisso_segreto`. L'attaccante può scegliere il prefisso ma non conosce il suffisso. L'obiettivo è recuperare il suffisso segreto byte per byte.

Il principio è il seguente: se fornico un input di `n-1` byte (dove `n` è la dimensione del blocco), l'oracolo cifrerà il blocco `[miei (n-1) byte || primo byte del suffisso]`. Posso precomputare il cifrato di tutti i 256 possibili blocchi `[miei (n-1) byte || X]` per ogni valore di X da 0 a 255, e confrontare con il risultato reale per trovare il valore del primo byte del suffisso. Una volta noto il primo byte, posso usare `n-2` byte di mio input per esporre il secondo byte, e così via.

Questa tecnica è applicabile a qualsiasi sistema che: usa ECB, cifra `attacker_controlled || secret` con la stessa chiave ogni volta, e restituisce il cifrato. Molti cookie di sessione e token web degli anni 2000 erano vulnerabili a questo attacco.

La versione "semplice" (sfida 12) non ha prefisso controllato dall'oracolo. La versione "difficile" (sfida 14) aggiunge un prefisso casuale che deve essere prima neutralizzato.

## Concetti chiave

- **Byte-at-a-time decryption**: tecnica che recupera un suffisso segreto un byte alla volta manipolando l'allineamento dei blocchi.
- **`get_suffix`**: metodo di `CustomCrypter12` che implementa l'attacco completo per recuperare il suffisso.
- **`prefix_plus_suffix_length`**: metodo che calcola la lunghezza totale di prefisso + suffisso tramite il comportamento del padding.
- **`prefix_length`**: metodo che calcola la lunghezza del prefisso dell'oracolo.
- **Allineamento dei blocchi**: manipolazione della lunghezza dell'input per posizionare il byte target all'inizio di un nuovo blocco.
- **`chunks_count`**: metodo del trait `USizeCrypt` che calcola quanti blocchi completi occupano N byte e quanti byte mancano all'allineamento.

## Spiegazione del codice

### Struttura generale

La sfida usa `src/crypters/custom_crypter_12.rs` per l'oracolo e `src/usizecrypt/mod.rs` per le utility di allineamento.

### Implementazione

`get_suffix` recupera il suffisso segreto byte per byte:

```rust
pub fn get_suffix(&self) -> Result<Vec<u8>, JlmCryptoErrors> {
    let prefix_len = self.prefix_length().unwrap();
    let suffix_len = self.prefix_plus_suffix_length().unwrap() - prefix_len;
    let (prefix_chunks_count, prefix_fill_len) = prefix_len.chunks_count();
    let mut suffix = Vec::new();
    let mut input = vec![0; prefix_fill_len + Self::BLOCK_SIZE - 1];
    let virtual_ciphertexts = (0..Self::BLOCK_SIZE)
        .map(|left_shift| self.base.encrypt(&input[left_shift..]))
        .collect::<Result<Vec<Vec<u8>>, JlmCryptoErrors>>()
        .unwrap();
    for i in 0..suffix_len {
        let block_index = prefix_chunks_count + i / Self::BLOCK_SIZE;
        let left_shift = i % Self::BLOCK_SIZE;
        for u in 0u8..=255 {
            input.push(u);
            if virtual_ciphertexts[left_shift][block_index * Self::BLOCK_SIZE..(block_index + 1) * Self::BLOCK_SIZE]
                == self.base.encrypt(&input[left_shift..]).unwrap()[block_index * Self::BLOCK_SIZE..(block_index + 1) * Self::BLOCK_SIZE]
            {
                suffix.push(u);
                break;
            }
            input.pop();
        }
    }
    Ok(suffix)
}
```

Per ogni byte `i` del suffisso, calcola il blocco in cui si trova (`block_index`) e lo shift (`left_shift`). Confronta il blocco corrispondente del virtual ciphertext (precomputato) con il blocco del cifrato ottenuto aggiungendo il byte candidato `u`. Quando trovano corrispondenza, il byte è trovato.

### Il test

```rust
#[test]
pub fn challenge_12() {
    let oracle = CustomCrypter12::new();
    let base64_suffix = Base64::from_string(String::from(
        "Um9sbGluJyBpbiBteSA1LjAK..."
    ));
    match oracle {
        Ok(r) => {
            let input: Vec<u8> = b"A".to_vec();
            let encrypted_value = r.base.encrypt(&input).unwrap();
            assert_eq!(encrypted_value.len() % 16, 0);
            assert_eq!(base64_suffix, Base64::from_bytes(r.get_suffix().unwrap().as_slice()))
        }
        Err(_) => panic!(),
    }
}
```

Verifica che il suffisso recuperato corrisponda al suffisso Base64 noto ("Rollin' in my 5.0...").

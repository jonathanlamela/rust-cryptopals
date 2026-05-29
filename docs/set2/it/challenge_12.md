---
layout: default
title: "Sfida 12 — Byte-at-a-time ECB decryption (semplice)"
parent: "Set 2 — IT"
nav_order: 4
permalink: /set2/it/challenge_12/
lang: it
---

# Sfida 12 — Byte-at-a-time ECB decryption (semplice)

[← Sfida precedente](../challenge_11/) · [Sfida successiva →](../challenge_13/) · [🇬🇧 English](../../en/challenge_12/) · [Indice Set 2](../)

---

## Teoria

L'attacco "byte-at-a-time ECB decryption" è uno degli attacchi oracle più eleganti contro la modalità ECB. L'oracle in questione cifra la concatenazione di un plaintext controllato dall'attaccante con un suffisso segreto, usando sempre la stessa chiave casuale e la modalità ECB. L'attaccante non conosce la chiave né il suffisso, ma può interrogare l'oracle con qualsiasi input.

L'attacco funziona così: per estrarre il primo byte del suffisso, si invia un plaintext di 15 byte (un blocco meno uno). Il primo blocco cifrato contiene 15 byte controllati + il primo byte del suffisso. Si prova tutti i 256 possibili valori dell'ultimo byte: quello che produce lo stesso primo blocco cifrato rivela il valore del primo byte del suffisso. Si ripete con 14 byte di padding per il secondo byte, e così via.

La potenza di questo attacco sta nella sua efficienza: per un suffisso di N byte, bastano al più 256*N interrogazioni all'oracle — un numero lineare. Rispetto alla forza bruta su tutto il testo cifrato, questo è enormemente più efficiente.

Il metodo `get_suffix` in `CustomCrypter12` implementa questo attacco in modo completo, gestendo anche il caso in cui ci sia un prefisso (che non è presente in questa sfida, ma lo diventa nella sfida 14).

## Concetti chiave

- **Byte-at-a-time decryption:** estrae il suffisso un byte alla volta usando l'oracle ECB.
- **Boundary block attack:** allinea il byte sconosciuto alla fine di un blocco noto.
- **`get_suffix`:** metodo che esegue l'attacco completo per estrarre il suffisso segreto.
- **`prefix_plus_suffix_length`:** determina la lunghezza totale del contenuto aggiunto dall'oracle.
- **`prefix_blocks_count`:** trova quanti blocchi occupa il prefisso.
- **`chunks_count`:** calcola il numero di blocchi e il riempimento necessario.

## Spiegazione del codice

### Struttura generale

`src/crypters/custom_crypter_12.rs` definisce `CustomCrypter12` con i metodi di attacco. `get_suffix` è il metodo principale; si appoggia su `prefix_length`, `prefix_plus_suffix_length` e `prefix_blocks_count`.

### Implementazione

`prefix_blocks_count` trova quanti blocchi occupa il prefisso:

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

Cifra `[0]` e `[1]`: i blocchi che contengono il prefisso sono identici (il prefisso non cambia), il blocco che contiene l'input differisce. Il primo blocco diverso indica la posizione del blocco che contiene l'input.

`get_suffix` esegue l'attacco:

```rust
pub fn get_suffix(&self) -> Result<Vec<u8>, JlmCryptoErrors> {
    let prefix_len = self.prefix_length().unwrap();
    let suffix_len = self.prefix_plus_suffix_length().unwrap() - prefix_len;
    let (prefix_chunks_count, prefix_fill_len) = prefix_len.chunks_count();
    let mut suffix = Vec::new();
    let mut input = vec![0; prefix_fill_len + Self::BLOCK_SIZE - 1];
    let virtual_ciphertexts = (0..Self::BLOCK_SIZE)
        .map(|left_shift| self.base.encrypt(&input[left_shift..]))
        .collect::<Result<Vec<Vec<u8>>, JlmCryptoErrors>>().unwrap();
    for i in 0..suffix_len {
        let block_index = prefix_chunks_count + i / Self::BLOCK_SIZE;
        let left_shift = i % Self::BLOCK_SIZE;
        for u in 0u8..=255 {
            input.push(u);
            if virtual_ciphertexts[left_shift]
                [block_index * Self::BLOCK_SIZE..(block_index + 1) * Self::BLOCK_SIZE]
                == self.base.encrypt(&input[left_shift..]).unwrap()
                    [block_index * Self::BLOCK_SIZE..(block_index + 1) * Self::BLOCK_SIZE]
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

Per ogni byte i del suffisso: calcola il `left_shift` (posizione entro il blocco corrente) e il `block_index` (quale blocco confrontare). Prova tutti i 256 valori, aggiungendo ogni candidato all'`input`, confrontando il blocco target del ciphertext virtuale con quello del ciphertext reale.

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
        Err(_) => { panic!(); }
    }
}
```

Il test verifica che il suffisso estratto corrisponda al suffisso Base64 noto (i testi rap di "Rollin' in my 5.0").

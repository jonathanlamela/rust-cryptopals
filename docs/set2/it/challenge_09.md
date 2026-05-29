---
layout: default
title: "Sfida 9 — Implementa padding PKCS#7"
parent: "Set 2 — IT"
nav_order: 1
permalink: /set2/it/challenge_09/
lang: it
---

# Sfida 9 — Implementa padding PKCS#7

[Sfida successiva →](../challenge_10/) · [🇬🇧 English](../../en/challenge_09/) · [Indice Set 2](../)

---

## Teoria

I cifrari a blocchi come AES operano su blocchi di dimensione fissa (16 byte per AES). Quando il plaintext non è un multiplo esatto della dimensione del blocco, è necessario aggiungere byte di "riempimento" (padding) per completare l'ultimo blocco. Lo standard PKCS#7 (Public-Key Cryptography Standards #7) definisce uno schema di padding semplice e non ambiguo.

Lo schema PKCS#7 funziona così: se sono necessari N byte di padding (con N tra 1 e la dimensione del blocco), si aggiungono esattamente N byte, ognuno con il valore N. Se il messaggio è già un multiplo della dimensione del blocco, si aggiunge un intero blocco di padding con tutti i byte uguali alla dimensione del blocco (per esempio, 16 byte con valore 0x10 per un blocco da 16). Questo garantisce che il padding sia sempre presente e rimovibile in modo non ambiguo.

Per rimuovere il padding, si legge l'ultimo byte del testo decifrato — il suo valore indica quanti byte di padding sono stati aggiunti. Si verifica che tutti gli ultimi N byte abbiano effettivamente il valore N, poi si rimuovono. Se la verifica fallisce, il padding è invalido (questo è fondamentale per l'attacco della sfida 17).

PKCS#7 è standard in TLS, S/MIME, e quasi tutti i protocolli crittografici che usano cifrari a blocchi. La sua corretta implementazione è fondamentale: un'implementazione non standard del padding è una fonte comune di vulnerabilità.

## Concetti chiave

- **PKCS#7:** schema di padding che aggiunge N byte con valore N per portare a multiplo della dimensione del blocco.
- **Padding invariant:** il padding è sempre presente, anche se il messaggio è già allineato al blocco.
- **Unpadding determinista:** l'ultimo byte indica la quantità di padding da rimuovere.
- **Validazione del padding:** tutti gli ultimi N byte devono avere il valore N.
- **`JlmCryptoErrors::PKCS7PaddingFailed`:** errore restituito se k < 2.
- **`JlmCryptoErrors::InvalidPadding`:** errore restituito se il padding non è valido.

## Spiegazione del codice

### Struttura generale

I metodi `pad`, `unpad` e `check_padding_valid` sono definiti nel trait `CryptoVec` in `src/cryptovec/mod.rs`. Il test in `src/set2.rs` verifica il padding su "YELLOW SUBMARINE" portandolo a 20 byte.

### Implementazione

Il metodo `pad`:

```rust
fn pad(&mut self, k: u8) -> Result<bool, JlmCryptoErrors> {
    if k < 2 {
        return Err(JlmCryptoErrors::PKCS7PaddingFailed);
    }
    let p = k - (self.len() % k as usize) as u8;
    for _ in 0..p {
        self.push(p);
    }
    Ok(true)
}
```

`k` è la dimensione del blocco. `self.len() % k as usize` è il numero di byte già presenti nell'ultimo blocco parziale. `p = k - (self.len() % k)` è il numero di byte di padding necessari. Se il messaggio è già allineato, `self.len() % k == 0` e `p = k` — si aggiunge un intero blocco di padding.

Il metodo `check_padding_valid`:

```rust
fn check_padding_valid(&self, k: u8) -> Result<bool, JlmCryptoErrors> {
    if k < 2 { return Err(JlmCryptoErrors::InvalidPadding); }
    if self.is_empty() || self.len() % k as usize != 0 {
        return Err(JlmCryptoErrors::InvalidPadding);
    }
    let padding = self[self.len() - 1];
    if !(1 <= padding && padding <= k) {
        return Err(JlmCryptoErrors::InvalidPadding);
    }
    let is_valid = self[self.len() - padding as usize..].iter().all(|&b| b == padding);
    if is_valid { Ok(true) } else { Err(JlmCryptoErrors::InvalidPadding) }
}
```

Verifica che il vettore sia non vuoto, sia un multiplo di k, che l'ultimo byte sia nell'intervallo `[1, k]`, e che tutti gli ultimi `padding` byte abbiano il valore `padding`.

Il metodo `unpad`:

```rust
fn unpad(&mut self, k: u8) -> Result<bool, JlmCryptoErrors> {
    if !self.check_padding_valid(k)? {
        return Err(JlmCryptoErrors::InvalidPadding);
    }
    let len_new = self.len() - self[self.len() - 1] as usize;
    self.truncate(len_new);
    Ok(true)
}
```

Dopo la validazione, calcola la nuova lunghezza e tronca il vettore.

### Il test

```rust
#[test]
fn challenge_9() {
    let size = 20;
    let mut string_to_pad = b"YELLOW SUBMARINE".to_vec();
    string_to_pad.pad(size).unwrap();
    assert_eq!(
        &string_to_pad,
        [89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4,].as_ref()
    )
}
```

"YELLOW SUBMARINE" ha 16 byte. Portandolo a 20 byte (k=20), servono 4 byte di padding. Il padding PKCS#7 aggiunge 4 byte con valore 4 (0x04). L'array atteso mostra esattamente questo.

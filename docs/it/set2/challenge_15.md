---
layout: default
title: "Sfida 15 — Convalida padding PKCS#7"
parent: "Set 2 IT"
grand_parent: IT
nav_order: 7
permalink: /it/set2/challenge_15/
lang: it
---

# Sfida 15 — Convalida padding PKCS#7

[← Sfida precedente](../challenge_14/) · [Sfida successiva →](../challenge_16/) · [🇬🇧 English](../../../en/set2/challenge_15/) · [Set 2](../) · [Home](../../)

---

## Teoria

La verifica del padding PKCS#7 è un'operazione critica in qualsiasi implementazione di cifratura a blocchi. Un'implementazione corretta deve verificare che: il byte finale del messaggio decifrato sia un valore di padding valido (tra 1 e block_size), e che tutti gli ultimi N byte abbiano lo stesso valore N.

Se il padding non è valido, il sistema deve restituire un errore. La tentazione di ignorare errori di padding o di gestirli in modo silenzioso è la causa del famoso "CBC padding oracle attack" (sfida 17): se il sistema risponde in modo diverso a padding valido vs. invalido, un attaccante può usare queste risposte diverse come oracolo per decifrare il messaggio.

La sfida 15 costruisce esattamente la funzione di verifica del padding che sarà poi sfruttata nella sfida 17. Capire perché questa funzione è corretta — e perché un'implementazione che non restituisce un errore ma restituisce semplicemente il testo non modificato sarebbe vulnerabile — è fondamentale.

Una nota sulla distinzione: `check_padding_valid` verifica senza modificare, `unpad` rimuove il padding dopo aver verificato. Entrambi usano lo stesso algoritmo di verifica ma con effetti collaterali diversi.

## Concetti chiave

- **Padding oracle**: vulnerabilità in cui il comportamento di errore del padding rivela informazioni sul testo in chiaro.
- **`check_padding_valid`**: metodo che verifica il padding PKCS#7 restituendo `Ok(true)` o `Err(InvalidPadding)`.
- **`unpad`**: metodo che rimuove il padding PKCS#7 dopo averlo verificato.
- **Errore di padding**: condizione che indica che il messaggio è corrotto o che il padding non è stato applicato correttamente.
- **Byte di padding**: l'ultimo byte del messaggio indica quanti byte di padding seguono (incluso se stesso).
- **Side channel**: canale di informazione non intenzionale che può essere sfruttato da un attaccante.

## Spiegazione del codice

### Struttura generale

La sfida usa esclusivamente `src/cryptovec/mod.rs`, metodi `check_padding_valid` e `unpad`.

### Implementazione

`check_padding_valid` è già stato analizzato nella sfida 9. La sua logica completa:

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
    let is_valid = self[self.len() - padding as usize..]
        .iter()
        .all(|&b| b == padding);
    if is_valid { Ok(true) } else { Err(JlmCryptoErrors::InvalidPadding) }
}
```

Nota che la funzione restituisce sempre `Result`: `Ok(true)` per padding valido, `Err` per qualsiasi forma di padding non valido. Non esiste un cammino "silenzioso" che restituisce il messaggio non modificato.

`unpad` usa `check_padding_valid` prima di troncare:

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

### Il test

```rust
#[test]
pub fn challenge_15() {
    let str1 = String::from("ICE ICE BABY\x04\x04\x04\x04");
    let str2 = String::from("ICE ICE BABY\x05\x05\x05\x05");
    let str3 = String::from("ICE ICE BABY\x05\x05\x05\x05");
    let mut str1_vec = str1.as_bytes().to_vec();
    let str2_vec = str2.as_bytes().to_vec();
    let str3_vec = str3.as_bytes().to_vec();
    assert_eq!(str1_vec.check_padding_valid(16).unwrap(), true);
    assert_eq!(str2_vec.check_padding_valid(16).is_err(), true);
    assert_eq!(str3_vec.check_padding_valid(16).is_err(), true);
    let _ = str1_vec.unpad(16);
    assert_eq!(String::from_utf8(str1_vec).unwrap(), "ICE ICE BABY");
}
```

`str1` ha padding valido: 4 byte con valore 4. `str2` e `str3` hanno padding invalido: i byte hanno valore 5 ma "ICE ICE BABY" è solo 12 byte, quindi `12 + 5 = 17 > 16` e il padding non è multiplo del blocco — restituisce errore. Dopo `unpad`, `str1` diventa "ICE ICE BABY".

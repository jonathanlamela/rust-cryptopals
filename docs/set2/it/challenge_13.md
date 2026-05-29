---
layout: default
title: "Sfida 13 — ECB cut-and-paste"
parent: "Set 2 — IT"
nav_order: 5
permalink: /set2/it/challenge_13/
lang: it
---

# Sfida 13 — ECB cut-and-paste

[← Sfida precedente](../challenge_12/) · [Sfida successiva →](../challenge_14/) · [🇬🇧 English](../../en/challenge_13/) · [Indice Set 2](../)

---

## Teoria

L'attacco ECB cut-and-paste sfrutta l'assenza di integrità in ECB: poiché ogni blocco è indipendente, un attaccante può riorganizzare i blocchi cifrati per produrre un plaintext diverso una volta decifrato. Non è necessario conoscere la chiave.

Lo scenario è un sistema di autenticazione che cifra i profili utente in ECB e li usa come cookie. Un profilo ha la forma `email=xxx&uid=10&role=user`. Il sistema sanitizza i caratteri `&` e `=` dall'email, ma non previene l'attacco cut-and-paste.

La strategia è in due fasi. Prima si crea un ciphertext dove il secondo blocco (byte 16–31) contiene la cifratura di `admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b` (la parola "admin" con padding PKCS#7 per raggiungere 16 byte). Poi si crea un secondo ciphertext con un'email fatta apposta per far terminare `email=xxx&uid=10&role=` esattamente a un confine di blocco. Sostituendo l'ultimo blocco di questo secondo ciphertext con il blocco "admin" estratto dal primo, il plaintext decifrato termina con `role=admin` invece di `role=user`.

Questo attacco dimostra che la confidenzialità senza integrità è insufficiente. Un sistema sicuro deve usare MAC (Message Authentication Code) o cifratura autenticata (AEAD) per garantire che il ciphertext non possa essere modificato.

## Concetti chiave

- **ECB cut-and-paste:** riorganizzazione di blocchi ECB per ottenere un plaintext diverso.
- **Assenza di integrità:** ECB non ha meccanismi per rilevare modifiche al ciphertext.
- **Boundary alignment:** l'email è scelta per allineare `role=` alla fine di un blocco.
- **`profile_for`:** costruisce la stringa di profilo dall'email (con sanitizzazione).
- **`generate_test_email`:** genera un'email di lunghezza opportuna per l'attacco.
- **Padding PKCS#7 come dati:** inserisce il padding come parte del plaintext controllato.

## Spiegazione del codice

### Struttura generale

`src/crypters/custom_crypter_13.rs` definisce `CustomCrypter13` con la cifratura ECB e i metodi di costruzione del profilo. Il test in `src/set2.rs` esegue l'attacco manualmente.

### Implementazione

`CustomCrypter13::new`:

```rust
pub fn new() -> Result<Self, JlmCryptoErrors> {
    let block_size: usize = 16;
    let key = block_size.random_block();
    Ok(CustomCrypter13 {
        base: OracleBase {
            key: key,
            prefix: Some(b"email=".to_vec()),
            suffix: Some(b"&uid=10&role=user".to_vec()),
            iv: None,
            mode: MODE::ECB,
        },
    })
}
```

Prefisso fisso `email=` e suffisso fisso `&uid=10&role=user`. La cifratura in `CustomCrypter13::encrypt` usa ECB direttamente sull'input (la stringa di profilo serializzata).

`profile_for` sanitizza l'input e costruisce la stringa:

```rust
pub fn profile_for(&self, email: String) -> Result<String, JlmCryptoErrors> {
    if email.contains("&") {
        return Err(JlmCryptoErrors::InvalidSet2Challenge13Chars);
    } else {
        let mut result_string = String::from("email=");
        result_string.push_str(&email);
        result_string.push_str("&uid=10&role=user");
        Ok(result_string)
    }
}
```

### Il test

```rust
#[test]
pub fn challenge_13() {
    let oracle13 = CustomCrypter13::new().unwrap();
    let email = &String::from(oracle13.generate_test_email());
    let junk1: Vec<u8> = vec![65u8; 10];
    let mut admin_with_padding = b"admin".to_vec();
    let padding = vec![11; 11];
    admin_with_padding.extend_from_slice(&padding[..]);
    let mut test_bytes = Vec::new();
    test_bytes.extend_from_slice(&junk1[..]);
    test_bytes.extend_from_slice(&admin_with_padding[..]);
    let ciphertext1 = &oracle13.encrypt(
        &oracle13.profile_for(String::from_utf8(test_bytes[..].to_vec()).unwrap()).unwrap().as_bytes(),
    ).unwrap();
    let mut ciphertext1_chunks = ciphertext1.chunks(16);
    let ciphertext2 = &mut oracle13.encrypt(
        &oracle13.profile_for(email.to_string()).unwrap().as_bytes()
    ).unwrap();
    let last_block = ciphertext1_chunks.nth(1).unwrap();
    ciphertext2.truncate(32);
    ciphertext2.extend_from_slice(&last_block);
    let new_cookie_decrypted = ciphertext2.to_vec()
        .ssl_ecb_decrypt(&oracle13.base.key, Some(true)).unwrap();
    assert!(String::from_utf8(new_cookie_decrypted).unwrap().ends_with("role=admin"));
}
```

L'attacco in dettaglio: `junk1` di 10 'A' allinea `admin\x0b...\x0b` al secondo blocco (byte 16–31). `generate_test_email` produce un'email di 9 caratteri (`xxxx@yyyy.com`) che porta `email=xxxx@yyyy.com&uid=10&role=` a esattamente 32 byte (2 blocchi). Si sostituisce il terzo blocco di `ciphertext2` con il secondo blocco di `ciphertext1`.

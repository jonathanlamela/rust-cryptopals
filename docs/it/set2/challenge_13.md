---
layout: default
title: "Sfida 13 — ECB cut-and-paste"
parent: "Set 2 IT"
grand_parent: IT
nav_order: 5
permalink: /it/set2/challenge_13/
lang: it
---

# Sfida 13 — ECB cut-and-paste

[← Sfida precedente](../challenge_12/) · [Sfida successiva →](../challenge_14/) · [🇬🇧 English](../../../en/set2/challenge_13/) · [Set 2](../) · [Home](../../)

---

## Teoria

L'attacco ECB cut-and-paste sfrutta la proprietà di ECB per cui ogni blocco è cifrato e decifrato indipendentemente. Se si riesce a far cifrare all'oracolo un blocco che contiene esattamente il valore desiderato (ad es. "admin"), si può "tagliare" quel blocco dal cifrato e "incollarlo" in un altro cifrato per produrre un messaggio manipolato.

In questa sfida, l'oracolo crea profili utente nel formato `email=...&uid=10&role=user`, cifrati in ECB. Il goal è produrre un profilo con `role=admin`. Per farlo, si seguono questi passi:

1. Si crea un'email il cui valore, dopo `email=`, posiziona il blocco successivo all'inizio di un nuovo blocco. Ad esempio, con `email=` (6 byte) più 10 byte di junk = 16 byte (un blocco completo). Il secondo blocco inizierà con il testo controllato.
2. Si usa come email `AAAAAAAAAAadmin\x0b\x0b...\x0b` (10 byte di junk + "admin" + 11 byte di padding 0x0b). Il secondo blocco cifrato conterrà `encrypt("admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b")`.
3. Si crea un secondo profilo con un'email normale (es. 9 caratteri) tale che `email=...&uid=10&role=` sia esattamente 32 byte (2 blocchi), e il terzo blocco inizi con "user".
4. Si sostituisce il terzo blocco del secondo cifrato con il secondo blocco del primo cifrato.
5. Il risultato decifrato sarà `email=...&uid=10&role=admin`.

## Concetti chiave

- **ECB cut-and-paste**: attacco che riassembla blocchi cifrati da sessioni diverse per forgiare un messaggio malformato.
- **Blocco di confine**: allineamento preciso dell'input per far iniziare un valore target all'inizio di un blocco.
- **`CustomCrypter13`**: oracolo che crea profili cookie nel formato `email=...&uid=10&role=user`.
- **`profile_for`**: metodo che costruisce la stringa profilo, rifiutando input con `&` o `=`.
- **`generate_test_email`**: metodo che genera un'email di 9 caratteri per l'allineamento dei blocchi.
- **Padding manuale**: aggiunta di 11 byte di valore 0x0b per completare il blocco "admin".

## Spiegazione del codice

### Struttura generale

La sfida usa `src/crypters/custom_crypter_13.rs` per l'oracolo cookie e `src/cryptovec/mod.rs` per la cifratura ECB.

### Implementazione

`CustomCrypter13` usa un `OracleBase` con prefisso `b"email="` e suffisso `b"&uid=10&role=user"`:

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

`profile_for` crea il profilo validando l'email:

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

L'`impl Oracle for CustomCrypter13` cifra il byte slice ricevuto in ECB direttamente (non usa `OracleBase.encrypt` ma `ssl_ecb_encrypt` sul contenuto passato):

```rust
fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>, JlmCryptoErrors> {
    Ok(u.to_vec().ssl_ecb_encrypt(&self.base.key, Some(true)).unwrap())
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
    let ciphertext1 = &oracle13.encrypt(&oracle13.profile_for(String::from_utf8(test_bytes[..].to_vec()).unwrap()).unwrap().as_bytes()).unwrap();
    let mut ciphertext1_chunks = ciphertext1.chunks(16);
    let ciphertext2 = &mut oracle13.encrypt(&oracle13.profile_for(email.to_string()).unwrap().as_bytes()).unwrap();
    let last_block = ciphertext1_chunks.nth(1).unwrap();
    ciphertext2.truncate(32);
    ciphertext2.extend_from_slice(&last_block);
    let new_cookie_decrypted = ciphertext2.to_vec().ssl_ecb_decrypt(&oracle13.base.key, Some(true)).unwrap();
    assert!(String::from_utf8(new_cookie_decrypted).unwrap().ends_with("role=admin"));
}
```

Il test forgia un profilo admin estraendo il blocco cifrato contenente "admin" e incollandolo come terzo blocco di un profilo normale.

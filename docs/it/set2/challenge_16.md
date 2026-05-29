---
layout: default
title: "Sfida 16 — Bitflipping CBC"
parent: "Set 2 IT"
grand_parent: IT
nav_order: 8
permalink: /it/set2/challenge_16/
lang: it
---

# Sfida 16 — Bitflipping CBC

[← Sfida precedente](../challenge_15/) · [🇬🇧 English](../../../en/set2/challenge_16/) · [Set 2](../) · [Home](../../)

---

## Teoria

Il bitflipping attack su CBC sfrutta la proprietà matematica della decifratura CBC: `P[i] = D(C[i]) XOR C[i-1]`. Se un attaccante modifica un bit nel blocco cifrato `C[i-1]`, il corrispondente bit nel testo decifrato `P[i]` verrà invertito (XOR con 1). Il blocco `P[i-1]` sarà completamente corrotto (perché `D(C[i-1])` produrrà valori casuali), ma il blocco `P[i]` subirà modifiche precise e controllabili.

L'attaccante può quindi: fornire un testo in chiaro noto, cifarlo con CBC, modificare dei bit nel blocco cifrato precedente al blocco target, e ottenere un testo decifrato con il valore desiderato nel blocco target. Questo è un attacco di "malleabilità": anche senza conoscere la chiave, si può produrre un cifrato che decifra a un valore parzialmente controllato.

In questa sfida, l'oracolo aggiunge prefisso e suffisso al testo in chiaro e cita (quota) i caratteri `=` e `;`. L'attacco consiste nel: fornire il testo `\x00admin\x00true` (dove `\x00` sarà trasformato in `;` e `=` tramite bitflipping), cifrare, poi modificare i byte corretti nel blocco precedente per trasformare i `\x00` in `;` e `=`.

Il calcolo è: se vogliamo che il byte decifrato nel blocco `i` sia `target`, e il byte attuale (decifrato) è `current`, dobbiamo XOR-are il byte corrispondente del blocco cifrato `i-1` con `current XOR target`. Per `\x00 → ;`: XOR con `0 XOR 59 = 59`. Per `\x00 → =`: XOR con `0 XOR 61 = 61`.

## Concetti chiave

- **Bitflipping attack**: attacco che modifica bit specifici del testo cifrato CBC per alterare il testo decifrato in modo controllato.
- **Malleabilità**: proprietà di un sistema crittografico per cui i testi cifrati possono essere modificati per produrre testi decifrati modificabili.
- **`CustomCrypter16`**: struct che gestisce la preparazione della stringa con quoting dei caratteri speciali.
- **`prepare_string`**: metodo che aggiunge prefisso, input quotato e suffisso.
- **`quote_str` / `unquote_str`**: metodi che gestiscono l'escape e l'unescape dei caratteri `;` e `=`.
- **Propagazione dell'errore**: il blocco precedente al target sarà corrotto, ma il target sarà integro e modificato come desiderato.

## Spiegazione del codice

### Struttura generale

La sfida usa `src/crypters/custom_crypter_16.rs` per la preparazione del testo e `src/cryptovec/mod.rs` per cifratura e decifratura CBC.

### Implementazione

`CustomCrypter16::prepare_string` costruisce il testo in chiaro:

```rust
pub fn prepare_string(&self, input: &str) -> Vec<u8> {
    let input_quoted: String = self.quote_str(input);
    let input_bytes = input_quoted.as_bytes();
    let prepend_bytes = b"comment1=cooking%20MCs;userdata=";
    let append_bytes = b";comment2=%20like%20a%20pound%20of%20bacon";
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(&prepend_bytes[..]);
    plaintext.extend_from_slice(&input_bytes[..]);
    plaintext.extend_from_slice(&append_bytes[..]);
    plaintext
}
```

Il prefisso `"comment1=cooking%20MCs;userdata="` è esattamente 32 byte (2 blocchi). Quindi il testo dell'utente inizia nel terzo blocco. Il nostro input `"\x00admin\x00true"` sarà nel terzo blocco, e per modificarlo dobbiamo alterare il secondo blocco (byte 16 e 22 del cifrato).

Nel test, i byte 16 e 22 del cifrato vengono modificati con XOR per produrre `;` e `=`:

```rust
encrypted2[16] ^= 59; // ASCII di ';'
encrypted2[22] ^= 61; // ASCII di '='
```

Dopo la decifratura e l'unquoting, la stringa conterrà `;admin=true;`.

### Il test

```rust
#[test]
pub fn challenge_16() {
    let key_size: usize = 16;
    let iv: Vec<u8> = key_size.random_block();
    let key = key_size.random_block();
    let oracle = CustomCrypter16::new();
    // Prima parte: cifratura diretta con ;admin=true; nella stringa
    let plaintext1 = oracle.prepare_string("testing 123;admin=true;blah");
    let encrypted1 = plaintext1.ssl_cbc_encrypt(&key, &iv, Some(true)).unwrap();
    let decrypted1 = encrypted1.ssl_cbc_decrypt(&key, &iv, Some(true)).unwrap();
    let decrypted_string1 = String::from_utf8_lossy(&decrypted1);
    let unquoted1 = oracle.unquote_str(&decrypted_string1);
    assert_eq!(unquoted1.find(";admin=true;").is_some(), true);
    // Seconda parte: bitflipping
    let plaintext2 = oracle.prepare_string("\x00admin\x00true");
    let mut encrypted2 = plaintext2.ssl_cbc_encrypt(&key, &iv, Some(true)).unwrap();
    encrypted2[16] ^= 59;
    encrypted2[22] ^= 61;
    let decrypted2 = encrypted2.ssl_cbc_decrypt(&key, &iv, Some(true)).unwrap();
    let decrypted_string2 = String::from_utf8_lossy(&decrypted2);
    let unquoted2 = oracle.unquote_str(&decrypted_string2);
    assert_eq!(unquoted2.find(";admin=true;").is_some(), true);
}
```

La prima parte verifica che il quoting funzioni: `testing 123;admin=true;blah` ha i caratteri `;` e `=` quotati e poi unquotati, producendo di nuovo la stringa originale con `;admin=true;`. La seconda parte esegue l'attacco reale con bitflipping.

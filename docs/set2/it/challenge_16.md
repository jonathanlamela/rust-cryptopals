---
layout: default
title: "Sfida 16 — CBC bitflipping attacks"
parent: "Set 2 — IT"
nav_order: 8
permalink: /set2/it/challenge_16/
lang: it
---

# Sfida 16 — CBC bitflipping attacks

[← Sfida precedente](../challenge_15/) · [🇬🇧 English](../../en/challenge_16/) · [Indice Set 2](../)

---

## Teoria

L'attacco CBC bitflipping sfrutta la struttura della decifratura CBC: il plaintext di un blocco è il risultato della decifratura del blocco di ciphertext corrente XORato con il blocco di ciphertext precedente. Modificando un byte del blocco di ciphertext C[i], si modifica in modo prevedibile il corrispondente byte del plaintext P[i+1], al costo di "corrompere" completamente P[i].

La meccanica precisa è: `P[i+1][j] = Decrypt(C[i+1])[j] XOR C[i][j]`. Se si vuole che `P[i+1][j]` assuma un valore target `t`, e attualmente vale `v`, basta modificare `C[i][j]` con `C[i][j] XOR v XOR t`. Questo è deterministico e non richiede la conoscenza della chiave.

Nello scenario della sfida, l'oracle aggiunge prefisso e suffisso al plaintext e lo cifra in CBC. L'input viene "quotato" (i caratteri `;` e `=` vengono escapati). Il goal è produrre un ciphertext che, una volta decifrato e unquotato, contenga `;admin=true;`. Poiché `;` ha ASCII 59 (0x3b) e `=` ha ASCII 61 (0x3d), si possono usare i byte `\x00` al loro posto nell'input (che non vengono quotati), poi modificare il ciphertext per convertirli nei valori target.

Questo attacco dimostra che la CBC non offre integrità del messaggio: un attaccante che può modificare il ciphertext può alterare il plaintext in modo controllato. La soluzione corretta è l'uso di cifratura autenticata (ad esempio AES-GCM o ChaCha20-Poly1305).

## Concetti chiave

- **CBC bitflipping:** modifica prevedibile del plaintext alterando il ciphertext del blocco precedente.
- **`prepare_string`:** aggiunge prefisso/suffisso e quota i caratteri `;` e `=`.
- **`unquote_str`:** rimuove le quote introdotte da `quote_str`.
- **`CustomCrypter16`:** oracle per la preparazione e verifica delle stringhe.
- **XOR controllato:** `C[i][j] ^= target_char XOR current_char` per ottenere il carattere desiderato.
- **Corruzione del blocco precedente:** il blocco P[i] diventa spazzatura, ma P[i+1] è quello che ci interessa.

## Spiegazione del codice

### Struttura generale

`src/crypters/custom_crypter_16.rs` definisce `CustomCrypter16` con i metodi `prepare_string`, `quote_str`, e `unquote_str`. Il test in `src/set2.rs` esegue sia la verifica del quoting (parte 1) sia l'attacco bitflipping (parte 2).

### Implementazione

`quote_str` e `unquote_str`:

```rust
pub fn quote_str(&self, input: &str) -> String {
    let mut quoted_input = str::replace(input, ";", "\";\"");
    quoted_input = str::replace(&quoted_input[..], "=", "\"=\"");
    quoted_input
}

pub fn unquote_str(&self, input: &str) -> String {
    let mut quoted_input = str::replace(input, "\";\"", ";");
    quoted_input = str::replace(&quoted_input[..], "\"=\"", "=");
    quoted_input
}
```

Quoting: `;` diventa `";"` e `=` diventa `"="`. Questo impedisce iniezioni dirette di questi caratteri.

`prepare_string`:

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

Il prefisso `comment1=cooking%20MCs;userdata=` è di 32 byte (2 blocchi esatti), quindi l'input inizia al blocco 2.

### Il test

```rust
#[test]
pub fn challenge_16() {
    let key_size: usize = 16;
    let iv: Vec<u8> = key_size.random_block();
    let key = key_size.random_block();
    let oracle = CustomCrypter16::new();

    // Parte 1: quoting funziona
    let plaintext1 = oracle.prepare_string("testing 123;admin=true;blah");
    let encrypted1 = plaintext1.ssl_cbc_encrypt(&key, &iv, Some(true)).unwrap();
    let decrypted1 = encrypted1.ssl_cbc_decrypt(&key, &iv, Some(true)).unwrap();
    let decrypted_string1 = String::from_utf8_lossy(&decrypted1);
    let unquoted1 = oracle.unquote_str(&decrypted_string1);
    assert_eq!(unquoted1.find(";admin=true;").is_some(), true);

    // Parte 2: bitflipping
    let plaintext2 = oracle.prepare_string("\x00admin\x00true");
    let mut encrypted2 = plaintext2.ssl_cbc_encrypt(&key, &iv, Some(true)).unwrap();
    encrypted2[16] ^= 59;  // \x00 → ;  (59 = ASCII ';')
    encrypted2[22] ^= 61;  // \x00 → =  (61 = ASCII '=')
    let decrypted2 = encrypted2.ssl_cbc_decrypt(&key, &iv, Some(true)).unwrap();
    let decrypted_string2 = String::from_utf8_lossy(&decrypted2);
    let unquoted2 = oracle.unquote_str(&decrypted_string2);
    assert_eq!(unquoted2.find(";admin=true;").is_some(), true);
}
```

`encrypted2[16]` è il primo byte del secondo blocco di ciphertext. Modificandolo con XOR 59, il corrispondente byte del terzo blocco di plaintext (che contiene il nostro input `\x00admin\x00true`) cambia da `\x00` a `;`. Analogamente per `encrypted2[22]` → `=`.

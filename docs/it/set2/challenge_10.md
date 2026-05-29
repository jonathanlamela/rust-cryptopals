---
layout: default
title: "Sfida 10 — Implementa AES CBC"
parent: "Set 2 IT"
grand_parent: IT
nav_order: 2
permalink: /it/set2/challenge_10/
lang: it
---

# Sfida 10 — Implementa AES CBC

[← Sfida precedente](../challenge_09/) · [Sfida successiva →](../challenge_11/) · [🇬🇧 English](../../../en/set2/challenge_10/) · [Set 2](../) · [Home](../../)

---

## Teoria

La modalità CBC (Cipher Block Chaining) risolve la principale debolezza di ECB: il fatto che blocchi identici di testo in chiaro producano blocchi identici di testo cifrato. In CBC, prima di cifrare ogni blocco di testo in chiaro, si esegue uno XOR con il blocco di testo cifrato precedente. Per il primo blocco, si usa un vettore di inizializzazione (IV) al posto del blocco precedente.

La formula di cifratura CBC è: `C[i] = E(P[i] XOR C[i-1])` dove `C[0] = E(P[0] XOR IV)`. La formula di decifratura è: `P[i] = D(C[i]) XOR C[i-1]` dove `P[0] = D(C[0]) XOR IV`.

CBC ha proprietà importanti rispetto a ECB: blocchi identici di testo in chiaro producono cifrati diversi (grazie al chaining); un singolo bit di errore nel cifrato corrompe il blocco corrente e influenza un solo bit del blocco successivo (propagazione parziale degli errori). Tuttavia, CBC è sequenziale nella cifratura (ogni blocco dipende dal precedente) ma parallelizzabile nella decifratura.

L'IV deve essere casuale e non riutilizzato per garantire la sicurezza semantica: se due messaggi usano lo stesso IV e la stessa chiave, e i loro primi blocchi sono identici, il primo blocco cifrato sarà identico, rivelando informazioni. L'IV può essere trasmesso in chiaro insieme al cifrato senza comprometterne la sicurezza.

## Concetti chiave

- **CBC mode**: modalità in cui ogni blocco in chiaro è XORed con il blocco cifrato precedente prima della cifratura.
- **Initialization Vector (IV)**: valore casuale usato come "blocco cifrato fittizio" prima del primo blocco reale.
- **Chaining**: dipendenza di ogni blocco dal precedente che rompe la struttura deterministica di ECB.
- **`ssl_cbc_decrypt`**: metodo che usa OpenSSL per decifrare con AES-128-CBC.
- **`legacy_cbc_decrypt`**: implementazione manuale di CBC che usa ECB su ogni singolo blocco.
- **Sicurezza semantica**: proprietà per cui cifrare due messaggi identici produce cifrati diversi grazie all'IV casuale.

## Spiegazione del codice

### Struttura generale

La sfida usa `src/cryptovec/mod.rs`. Sono presenti due implementazioni: `legacy_cbc_decrypt` (manuale, per comprensione) e `ssl_cbc_decrypt`/`ssl_cbc_encrypt` (OpenSSL, per uso effettivo).

### Implementazione

`legacy_cbc_decrypt` implementa CBC manualmente:

```rust
fn legacy_cbc_decrypt(&self, key: &[u8], iv: &mut [u8]) -> Result<Vec<u8>, JlmCryptoErrors> {
    let block_size = 16;
    let mut plaintext = Vec::new();
    let mut prev_ciphertext_block = iv.to_vec();
    for chunk in self.chunks(block_size) {
        let decrypted_block = chunk.to_vec().ssl_ecb_decrypt(key, Some(false)).unwrap();
        let mut decrypted_block_xor = Vec::with_capacity(block_size);
        for j in 0..block_size {
            decrypted_block_xor.push(decrypted_block[j] ^ prev_ciphertext_block[j]);
        }
        prev_ciphertext_block = chunk.to_vec();
        plaintext.extend_from_slice(&decrypted_block_xor);
    }
    let _ = plaintext.unpad(16);
    Ok(plaintext)
}
```

Per ogni blocco cifrato: decifra con AES-ECB (senza padding, `Some(false)`), fa XOR con il blocco cifrato precedente (o IV per il primo), aggiorna `prev_ciphertext_block` al blocco cifrato corrente. Infine rimuove il padding.

`ssl_cbc_encrypt` usa OpenSSL per la cifratura:

```rust
fn ssl_cbc_encrypt(&self, key: &[u8], iv: &[u8], pad: Option<bool>) -> Result<Vec<u8>, JlmCryptoErrors> {
    let cipher = Cipher::aes_128_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv)).unwrap();
    crypter.pad(pad.unwrap_or(true));
    let mut encrypted = vec![0; &self.len() + cipher.block_size()];
    let count = crypter.update(&self, &mut encrypted).unwrap();
    match crypter.finalize(&mut encrypted[count..]) {
        Ok(final_count_value) => {
            encrypted.truncate(count + final_count_value);
            Ok(encrypted)
        }
        Err(_) => Err(JlmCryptoErrors::InvalidPadding),
    }
}
```

### Il test

```rust
#[test]
fn challenge_10() {
    let file_path = "./data/data_10.txt";
    let mut file = File::open(file_path).expect("Unable to read file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Error reading file.");
    let buffer_to_string = str::from_utf8(&buffer).unwrap().replace("\n", "");
    let input = Base64::from_string(buffer_to_string);
    let input_bytes = input.to_bytes().unwrap_or_else(|_| panic!("Invalid Base64 to bytes"));
    let iv = &[0; 16];
    if let Ok(v) = input_bytes.legacy_cbc_decrypt(b"YELLOW SUBMARINE", &mut iv.to_owned()) {
        let result = String::from_utf8(v).unwrap();
        assert_eq!(YELLOW_SUBMARINE_STRING, result)
    }
}
```

Decifra un file Base64 con AES-CBC usando IV di tutti zeri e chiave "YELLOW SUBMARINE". Il risultato atteso è di nuovo il testo di "Play That Funky Music".

---
layout: default
title: "Sfida 10 — Implementa CBC mode"
parent: "Set 2 — IT"
nav_order: 2
permalink: /set2/it/challenge_10/
lang: it
---

# Sfida 10 — Implementa CBC mode

[← Sfida precedente](../challenge_09/) · [Sfida successiva →](../challenge_11/) · [🇬🇧 English](../../en/challenge_10/) · [Indice Set 2](../)

---

## Teoria

La modalità CBC (Cipher Block Chaining) è stata progettata per risolvere la principale debolezza di ECB: la produzione di blocchi di ciphertext identici per blocchi di plaintext identici. In CBC, ogni blocco di plaintext viene XORato con il blocco di ciphertext precedente prima di essere cifrato con la chiave. Il primo blocco usa un valore speciale chiamato IV (Initialization Vector), che dovrebbe essere casuale e unico per ogni sessione.

Questa catena di dipendenze crea la proprietà di "diffusione": un singolo bit cambiato nel plaintext o nel ciphertext si propaga attraverso tutti i blocchi successivi, rendendo molto più difficile l'analisi statistica. A differenza di ECB, blocchi di plaintext identici producono blocchi di ciphertext diversi se preceduti da blocchi diversi.

Per la decifratura in CBC, il processo è inverso: ogni blocco di ciphertext viene decifrato con la chiave, poi XORato con il blocco di ciphertext precedente (o con l'IV per il primo blocco) per ottenere il plaintext. Questa asimmetria tra cifratura e decifratura ha implicazioni importanti per gli attacchi: la sfida 16 mostra come modificare il ciphertext possa influenzare prevedibilmente il plaintext decifrato.

Il codice implementa sia una versione "legacy" manuale (usando `ssl_ecb_decrypt` per ogni blocco) sia una versione OpenSSL che gestisce automaticamente l'intera modalità CBC.

## Concetti chiave

- **CBC (Cipher Block Chaining):** XOR del plaintext con il ciphertext precedente prima della cifratura.
- **IV (Initialization Vector):** valore casuale usato per il XOR del primo blocco; deve essere unico per ogni messaggio.
- **Diffusione:** un cambiamento in un blocco si propaga a tutti i blocchi successivi.
- **`legacy_cbc_decrypt`:** implementazione manuale di CBC usando ECB per ogni blocco.
- **`ssl_cbc_decrypt`/`ssl_cbc_encrypt`:** implementazione tramite OpenSSL.
- **Indipendenza della decifratura:** ogni blocco CBC può essere decifrato indipendentemente (a differenza della cifratura).

## Spiegazione del codice

### Struttura generale

`src/cryptovec/mod.rs` contiene sia `legacy_cbc_decrypt` (implementazione manuale) che `ssl_cbc_encrypt`/`ssl_cbc_decrypt` (implementazione OpenSSL). Il test usa OpenSSL per decifrare il file dati.

### Implementazione

Il metodo `legacy_cbc_decrypt` mostra la meccanica di CBC:

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

Per ogni blocco di ciphertext: (1) decifrare con AES-ECB senza padding (`Some(false)`); (2) fare XOR con il blocco di ciphertext precedente (inizialmente l'IV); (3) aggiornare il "blocco precedente" con il blocco di ciphertext corrente; (4) aggiungere il plaintext decifrato al risultato.

Il metodo `ssl_cbc_encrypt` usa OpenSSL direttamente:

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

La differenza rispetto a ECB è `Cipher::aes_128_cbc()` e `Some(iv)` nel costruttore di `Crypter`.

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

Il file contiene il ciphertext Base64 cifrato con AES-CBC, chiave "YELLOW SUBMARINE" e IV tutto zero. Il test decifra e verifica che il plaintext sia "Play That Funky Music".

---
layout: default
title: "Sfida 18 — Implementa CTR mode"
parent: "Set 3 — IT"
nav_order: 2
permalink: /set3/it/challenge_18/
lang: it
---

# Sfida 18 — Implementa CTR mode

[← Sfida precedente](../challenge_17/) · [Sfida successiva →](../challenge_19/) · [🇬🇧 English](../../en/challenge_18/) · [Indice Set 3](../)

---

## Teoria

La modalità CTR (Counter Mode) trasforma un cifrario a blocchi come AES in un cifrario a flusso. Invece di cifrare il plaintext direttamente, CTR cifra un contatore incrementale per generare un keystream, poi fa XOR del keystream con il plaintext. Il vantaggio fondamentale è che CTR è parallelizzabile: ogni blocco può essere cifrato indipendentemente, e la decifratura usa esattamente la stessa operazione della cifratura.

Il formato del contatore in questa implementazione è: 8 byte di nonce (un valore casuale usato una sola volta) seguiti da 8 byte di contatore in formato little-endian. Per il primo blocco, il contatore è 0; per il secondo blocco, è 1; e così via. Questo schema è simile al formato CTR usato in alcuni protocolli reali.

Una proprietà critica di CTR: il keystream dipende solo dalla chiave e dal nonce. Se lo stesso nonce viene riutilizzato con la stessa chiave, si ottiene lo stesso keystream, e qualsiasi modifica al ciphertext di un messaggio può essere trasferita all'altro — esattamente come un one-time pad riutilizzato. Le sfide 19 e 20 sfruttano questa debolezza.

Rispetto a CBC, CTR non richiede padding (i blocchi parziali vengono gestiti usando solo la porzione necessaria del keystream), non ha dipendenze tra blocchi (parallelizzabile) e permette l'accesso casuale al ciphertext.

## Concetti chiave

- **CTR mode:** cifrario a flusso basato su cifratura di un contatore incrementale.
- **Keystream:** sequenza pseudocasuale generata cifrando il contatore; usata per XOR con il plaintext.
- **Nonce:** numero usato una sola volta; garantisce keystream diversi per messaggi diversi.
- **Little-endian counter:** il contatore viene serializzato in formato little-endian a 64 bit.
- **`nonce_ctr_encrypt`:** implementazione di CTR con nonce esplicito usando `aessafe`.
- **`ssl_ctr_encrypt`/`ssl_ctr_decrypt`:** implementazione alternativa con OpenSSL.

## Spiegazione del codice

### Struttura generale

Il metodo `ssl_ctr_decrypt` in `src/cryptovec/mod.rs` usa un keystream incrementale. Il metodo `nonce_ctr_encrypt` usa la crate `crypto` (`aessafe`) per una implementazione più esplicita con nonce. Il test usa `ssl_ctr_decrypt`.

### Implementazione

`ssl_ctr_encrypt` (e il suo alias `ssl_ctr_decrypt`):

```rust
fn ssl_ctr_encrypt(&self, key: &[u8], pad: Option<bool>) -> Result<Vec<u8>, JlmCryptoErrors> {
    let mut ciphertext = Vec::new();
    let mut keystream = vec![0; 16];
    for b in self.chunks(16) {
        let to_xor = keystream.to_vec().ssl_ecb_encrypt(&key, pad);
        ciphertext.extend_from_slice(&b.to_vec().xor(to_xor.unwrap()));
        for b in keystream[16 / 2..].iter_mut() {
            *b += 1;
            if *b != 0 { break; }
        }
    }
    Ok(ciphertext)
}
```

Il keystream inizia tutto a zero. Per ogni blocco: cifra il keystream in ECB per ottenere il blocco di keystream, fa XOR con il blocco di plaintext/ciphertext, incrementa la seconda metà del keystream come contatore.

`nonce_ctr_encrypt` con nonce esplicito:

```rust
fn nonce_ctr_encrypt(&self, key: &[u8], nonce: Vec<u8>) -> Result<Vec<u8>, JlmCryptoErrors> {
    let block_size = key.len();
    let encryptor = aessafe::AesSafe128Encryptor::new(&key);
    let mut result: Vec<u8> = Vec::new();
    let mut keystream = vec![0; block_size];
    for (count, block) in self.chunks(block_size).enumerate() {
        let mut nonce_count = Vec::new();
        nonce_count.extend_from_slice(&nonce[..]);
        if let Ok(_) = nonce_count.write_u64::<LittleEndian>(count as u64) {
            encryptor.encrypt_block(&nonce_count[..], &mut keystream[..]);
            let b1 = &keystream[0..block.len()];
            let x_result = b1.to_vec().xor(block.to_vec());
            result.extend_from_slice(&x_result[..]);
        } else {
            return Err(JlmCryptoErrors::FailedAesCtrEncrypt);
        }
    }
    Ok(result)
}
```

Per ogni blocco, costruisce `nonce || counter` in little-endian, lo cifra con AES, e fa XOR con il blocco. `write_u64::<LittleEndian>` dalla crate `byteorder` serializza il contatore.

### Il test

```rust
#[test]
pub fn challenge_18() {
    let ciphertext = Base64::from_string(String::from(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
    ));
    let cleartext = ciphertext.to_bytes().unwrap()
        .ssl_ctr_decrypt(b"YELLOW SUBMARINE", Some(true)).unwrap();
    let result = String::from_utf8_lossy(&cleartext);
    assert_eq!(result, "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ")
}
```

Decifra il ciphertext Base64 con la chiave "YELLOW SUBMARINE" in CTR mode e verifica il plaintext atteso.

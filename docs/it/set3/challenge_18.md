---
layout: default
title: "Sfida 18 — Implementa AES CTR"
parent: "Set 3 IT"
grand_parent: IT
nav_order: 2
permalink: /it/set3/challenge_18/
lang: it
---

# Sfida 18 — Implementa AES CTR

[← Sfida precedente](../challenge_17/) · [Sfida successiva →](../challenge_19/) · [🇬🇧 English](../../../en/set3/challenge_18/) · [Set 3](../) · [Home](../../)

---

## Teoria

La modalità CTR (Counter) trasforma AES da cifrario a blocchi in cifrario a flusso. L'idea è semplice ma potente: invece di cifrare direttamente il testo in chiaro, si cifra una sequenza di contatori e si usa il risultato come keystream. Il testo cifrato è poi l'XOR tra il testo in chiaro e il keystream.

La struttura del blocco contatore è: `nonce (8 byte) || counter (8 byte in little-endian)`. Per il primo blocco, il contatore è 0; per il secondo, 1; e così via. Poiché si sta cifrando il contatore (non il testo in chiaro), la cifratura e la decifratura sono la stessa operazione: XOR con il keystream. Questo è uno dei principali vantaggi di CTR.

CTR ha proprietà eccellenti: è parallelizzabile sia in cifratura che in decifratura (ogni blocco di keystream può essere calcolato indipendentemente), permette accesso casuale (si può decifrare il blocco N senza decifrare i blocchi precedenti), e non richiede padding (il keystream ha la stessa lunghezza del testo in chiaro). Tuttavia, il nonce non deve mai essere riutilizzato con la stessa chiave: se due messaggi usano lo stesso nonce, il keystream è lo stesso, e lo XOR dei due cifrati è lo XOR dei due testi in chiaro — la stessa debolezza dello XOR a chiave ripetuta.

## Concetti chiave

- **Modalità CTR**: cifrario a flusso basato su AES che cifra contatori invece del testo in chiaro.
- **Nonce**: valore casuale usato una sola volta per garantire unicità del keystream.
- **Keystream**: sequenza di byte pseudo-casuali generata cifrando i contatori, usata per XOR col testo.
- **`ssl_ctr_decrypt`**: metodo di `CryptoVec` che implementa CTR usando lo stesso meccanismo di `ssl_ctr_encrypt`.
- **`nonce_ctr_encrypt`**: implementazione CTR con nonce esplicito usando il crate `crypto` (aessafe).
- **Little-endian counter**: il contatore a 8 byte è scritto in formato little-endian nel blocco nonce.

## Spiegazione del codice

### Struttura generale

La sfida usa `src/cryptovec/mod.rs`, metodi `ssl_ctr_decrypt` e `nonce_ctr_encrypt`. La prima usa OpenSSL, la seconda il crate `rust-crypto` con `aessafe::AesSafe128Encryptor`.

### Implementazione

`ssl_ctr_encrypt` (usata anche per la decifratura):

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

Il keystream inizia come 16 byte a zero. Per ogni blocco del testo, cifra il keystream con AES-ECB, fa XOR con il blocco di testo, poi incrementa il contatore nella seconda metà del keystream (simulando il little-endian del contatore a 8 byte).

`nonce_ctr_encrypt` usa `aessafe` per un'implementazione più esplicita:

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

Decifra un ciphertext Base64 con AES-CTR e verifica il testo recuperato.

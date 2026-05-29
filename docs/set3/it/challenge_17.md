---
layout: default
title: "Sfida 17 — The CBC padding oracle"
parent: "Set 3 — IT"
nav_order: 1
permalink: /set3/it/challenge_17/
lang: it
---

# Sfida 17 — The CBC padding oracle

[Sfida successiva →](../challenge_18/) · [🇬🇧 English](../../en/challenge_17/) · [Indice Set 3](../../)

---

## Teoria

L'attacco CBC padding oracle è uno degli attacchi crittografici più importanti e pratici mai scoperti, pubblicato da Vaudenay nel 2002. Permette di decifrare qualsiasi ciphertext CBC senza conoscere la chiave, usando solo la risposta dell'oracle ("padding valido" o "padding non valido").

Il meccanismo si basa sulla struttura di CBC: per decifrare un blocco C[i], si calcola `D[i] = AES_Decrypt(C[i])`, poi il plaintext è `P[i] = D[i] XOR C[i-1]`. Se si modifica C[i-1] e si invia il blocco modificato all'oracle, si può dedurre il valore di `D[i]`.

Per scoprire l'ultimo byte di D[i], si modifica l'ultimo byte di C[i-1] per tutti i 256 valori possibili. Il valore `u` che produce padding valido (ovvero `\x01`) soddisfa `D[i][15] XOR (C[i-1][15] XOR u) = 1`, da cui `D[i][15] = 1 XOR C[i-1][15] XOR u`. Conoscendo `D[i][15]`, si ricava `P[i][15] = D[i][15] XOR C[i-1][15]`.

Si procede poi per il penultimo byte, impostando il padding a `\x02\x02`, e così via. Il costo totale è al più `256 * BLOCK_SIZE * N_BLOCKS` query all'oracle — fattibile per ciphertext di dimensioni ragionevoli.

Questo attacco ha avuto implicazioni enormi sulla pratica crittografica. Ha portato alla deprecazione di CBC con padding PKCS#7 senza autenticazione e all'adozione di cifratura autenticata (AEAD).

## Concetti chiave

- **Padding oracle:** sistema che rivela se il padding di un ciphertext è valido.
- **Attacco di Vaudenay:** decifratura CBC usando solo il feedback sul padding.
- **`D[i]`:** output grezzo di AES_Decrypt sul blocco i (prima del XOR con il blocco precedente).
- **Manipolazione del blocco precedente:** cambiare C[i-1] cambia prevedibilmente P[i].
- **`ssl_cbc_decrypt` come oracle:** restituisce `Err(InvalidPadding)` per padding non valido.
- **`CustomCrypter17`:** classe con token predefiniti da decifrare.

## Spiegazione del codice

### Struttura generale

`src/crypters/custom_crypter_17.rs` definisce `CustomCrypter17` con un array di 10 token Base64. Il test in `src/set3.rs` implementa l'attacco padding oracle completo.

### Implementazione

Il loop dell'attacco padding oracle nel test:

```rust
for (block_index, block) in chunks.enumerate() {
    let block_offset = block_index * BLOCK_SIZE;
    for i in (0..BLOCK_SIZE).rev() {
        let padding = (BLOCK_SIZE - i) as u8;
        let t = [(padding - 1) ^ padding];
        let xor_res = prev[i + 1..].to_vec().xor_single(t[0]);
        prev[i + 1..].copy_from_slice(&xor_res);
        for u in 0u8..=255 {
            prev[i] ^= u;
            let value_decrypted = block.to_vec().ssl_cbc_decrypt(&key, &prev, Some(true));
            if value_decrypted.is_ok()
                && (i < BLOCK_SIZE - 1 || {
                    prev[i - 1] ^= 1;
                    let result = block.to_vec().ssl_cbc_decrypt(&key, &prev, Some(true));
                    prev[i - 1] ^= 1;
                    result.is_ok()
                })
            {
                let new_content = padding ^ u;
                cleartext_encrypted[block_offset + i] = new_content;
                break;
            }
            prev[i] ^= u;
        }
    }
    prev = block.to_vec();
}
```

Il ciclo esterno itera sui blocchi. Per ogni blocco, il ciclo interno itera sui byte da destra a sinistra (`rev()`). Per ogni posizione i: calcola il padding target `padding = BLOCK_SIZE - i`; aggiusta i byte già trovati per produrre il padding corretto (`xor_res`); prova tutti i 256 valori di `u` modificando `prev[i]` finché `ssl_cbc_decrypt` non restituisce `Ok`. Il controllo speciale per `i == BLOCK_SIZE - 1` (ultimo byte) gestisce l'ambiguità del padding `\x01` — si verifica che anche `prev[i-1] ^= 1` non rompa la validità.

### Il test

```rust
#[test]
pub fn challenge_17() {
    let crypter = CustomCrypter17::new().unwrap();
    const BLOCK_SIZE: usize = 16;
    let key = BLOCK_SIZE.random_block();
    let iv = BLOCK_SIZE.random_block();
    let clear_value = Base64::from_string(crypter.get_all_tokens().get(8).unwrap().to_string());
    let clear_bytes = clear_value.to_bytes().unwrap();
    let encrypted_value = clear_bytes.to_vec().ssl_cbc_encrypt(&key, &iv, Some(false));
    // ... attacco ...
    assert_eq!(decrypted_first.unwrap(), decrypted_second.unwrap());
}
```

Il test usa il token 8 (`ollin' in my five point oh`). Cifra con una chiave casuale, esegue l'attacco padding oracle, e verifica che il plaintext recuperato sia uguale a quello originale decifrato.

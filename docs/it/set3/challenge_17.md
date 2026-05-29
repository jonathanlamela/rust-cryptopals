---
layout: default
title: "Sfida 17 — CBC padding oracle"
parent: "Set 3 IT"
grand_parent: IT
nav_order: 1
permalink: /it/set3/challenge_17/
lang: it
---

# Sfida 17 — CBC padding oracle

[Sfida successiva →](../challenge_18/) · [🇬🇧 English](../../../en/set3/challenge_17/) · [Set 3](../) · [Home](../../)

---

## Teoria

Il CBC padding oracle attack è uno degli attacchi crittografici più famosi e praticamente rilevanti mai scoperti. Proposto da Vaudenay nel 2002, sfrutta un'unica informazione binaria: se il padding PKCS#7 di un messaggio decifrato è valido o non valido. Con questa sola informazione, un attaccante può decifrare qualsiasi messaggio CBC senza conoscere la chiave.

Il principio matematico è elegante. Dato un blocco cifrato `C[i]`, si vuole trovare il testo in chiaro `P[i] = D(C[i]) XOR C[i-1]`. Si chiama `D(C[i])` il risultato della decifratura AES del blocco (senza lo XOR con il precedente). L'attacco modifica `C[i-1]` un byte alla volta.

Per trovare l'ultimo byte di `P[i]`: si prende il blocco cifrato `C[i]` e si modifica l'ultimo byte di `C[i-1]` (chiamiamolo `r`) provando tutti i 256 valori. Per ogni valore `r`, si decifra il blocco `C[i]` con il `C[i-1]` modificato. Quando il padding è valido con valore 1 (un solo byte di padding uguale a `\x01`), si sa che `D(C[i])[ultimo byte] XOR r = 0x01`, quindi `D(C[i])[ultimo byte] = r XOR 0x01`. Da questo si ottiene `P[i][ultimo byte] = D(C[i])[ultimo byte] XOR C[i-1][ultimo byte]`.

Per trovare il penultimo byte, si imposta l'ultimo byte del `C[i-1]` modificato in modo che il padding sia `\x02\x02` (due byte di padding), e si cicla sul penultimo byte. E così via per tutti i 16 byte del blocco.

## Concetti chiave

- **Padding oracle**: sistema che rivela se il padding è valido (senza rivelare il testo in chiaro).
- **`D(C[i])`**: risultato della decifratura AES del blocco senza lo XOR col blocco precedente.
- **Attacco iterativo**: recupero byte per byte del testo in chiaro modificando il blocco cifrato precedente.
- **`CustomCrypter17`**: struct che fornisce i token da decifrare e le funzioni di cifratura/decifratura.
- **Propagazione del padding**: modifica del blocco precedente per indurre pattern di padding specifici.
- **`ssl_cbc_decrypt` con `Some(true)`**: decifratura che verifica il padding e restituisce errore se invalido — l'informazione sfruttata dall'oracolo.

## Spiegazione del codice

### Struttura generale

La sfida usa `src/crypters/custom_crypter_17.rs` per i token e `src/cryptovec/mod.rs` per cifratura e decifratura CBC. L'attacco è implementato direttamente nel test in `src/set3.rs`.

### Implementazione

Il cuore dell'attacco è il doppio ciclo annidato nel test. Per ogni blocco del cifrato, e per ogni byte all'interno del blocco (dall'ultimo al primo):

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

Il check aggiuntivo `prev[i - 1] ^= 1` per il caso `i == BLOCK_SIZE - 1` è necessario per evitare falsi positivi: quando si cerca il valore dell'ultimo byte, potrebbe esistere un valore `u` che produce padding valido `\x02\x02` invece di `\x01`. Modificando il penultimo byte e verificando che il padding non cambi, si conferma che si tratta davvero di un padding `\x01`.

### Il test

Il test cifra un token con chiave e IV casuali, applica l'attacco padding oracle per recuperare il testo in chiaro, poi verifica che il testo recuperato corrisponda al testo originale decifrato con la chiave corretta.

---
layout: default
title: "Sfida 11 — Oracle ECB/CBC — rileva la modalità"
parent: "Set 2 — IT"
nav_order: 3
permalink: /set2/it/challenge_11/
lang: it
---

# Sfida 11 — Oracle ECB/CBC — rileva la modalità

[← Sfida precedente](../challenge_10/) · [Sfida successiva →](../challenge_12/) · [🇬🇧 English](../../en/challenge_11/) · [Indice Set 2](../)

---

## Teoria

Un "oracle" crittografico è un sistema che esegue operazioni crittografiche su input forniti dall'attaccante, senza rivelare la chiave. In questa sfida, l'oracle aggiunge un prefisso e un suffisso casuali al plaintext, poi lo cifra con una chiave casuale usando ECB o CBC — scelta casualmente. Il compito è determinare quale modalità è stata usata.

La tecnica di rilevamento sfrutta ancora una volta la debolezza di ECB: se si fornisce un input sufficientemente lungo e ripetitivo (come 48 byte tutti uguali), è quasi certo che almeno due blocchi adiacenti del plaintext (dopo l'aggiunta del prefisso) siano identici. In ECB, blocchi di plaintext identici producono blocchi di ciphertext identici. In CBC, l'effetto di chaining rende i blocchi ciphertext diversi anche per plaintext identici.

L'input di 48 byte di zeri garantisce che, indipendentemente dalla lunghezza del prefisso (5–10 byte), ci siano almeno 32 byte consecutivi di zeri nel plaintext dopo il prefisso — cioè almeno due blocchi da 16 byte identici. Se nel ciphertext si trovano due blocchi consecutivi identici, la modalità è ECB.

Questo dimostra un principio fondamentale della sicurezza per progettazione: il sistema reale non rivela la chiave né la modalità, ma un attaccante può dedurre informazioni critiche semplicemente osservando come il ciphertext cambia in risposta a input controllati.

## Concetti chiave

- **Oracle crittografico:** sistema che cifra input forniti dall'attaccante senza rivelare la chiave.
- **`CustomCrypter11`:** oracle con modalità (ECB/CBC) e chiave casuali.
- **Rilevamento ECB tramite input ripetitivo:** input di blocchi identici → blocchi ciphertext identici in ECB.
- **`is_ecb_calculated`:** confronta i blocchi 1 e 2 (0-indexed) del ciphertext.
- **`USizeCrypt::random_block`:** genera un vettore di byte casuali di lunghezza `usize`.
- **Prefisso/suffisso casuali:** rendono il rilevamento più realistico (il plaintext non inizia all'inizio del blocco).

## Spiegazione del codice

### Struttura generale

`src/crypters/custom_crypter_11.rs` definisce `CustomCrypter11`, che usa `OracleBase` (`src/oracle/base.rs`) per la cifratura. Il test in `src/set2.rs` crea l'oracle, invia un input noto e verifica il rilevamento della modalità.

### Implementazione

`CustomCrypter11::new`:

```rust
pub fn new() -> Result<Self, JlmCryptoErrors> {
    let mut random_generator = thread_rng();
    let mut cipher: Cipher = Cipher::aes_128_ecb();
    let mode: MODE = if random_generator.gen() {
        MODE::ECB
    } else {
        cipher = Cipher::aes_128_cbc();
        MODE::CBC
    };
    let key = cipher.block_size().random_block();
    let prefix: Vec<u8> = random_generator.gen_range(5..=10).random_block();
    let suffix: Vec<u8> = random_generator.gen_range(5..=10).random_block();
    let iv: Option<Vec<u8>> = if mode == MODE::CBC {
        Some(cipher.block_size().random_block())
    } else { None };
    Ok(CustomCrypter11 { base: OracleBase { key, prefix: Some(prefix), suffix: Some(suffix), mode, iv } })
}
```

`thread_rng().gen()` produce un booleano casuale per scegliere la modalità. `random_block()` dal trait `USizeCrypt` genera byte casuali.

`is_ecb_calculated` rileva ECB:

```rust
pub fn is_ecb_calculated(&self, vec: Vec<u8>) -> Result<bool, JlmCryptoErrors> {
    let blocks: Vec<&[u8]> = vec.chunks(16).skip(1).take(2).collect();
    Ok(blocks[0] == blocks[1])
}
```

Salta il primo blocco (potrebbe essere parzialmente influenzato dal prefisso) e confronta il secondo e il terzo. Se sono uguali, la modalità è ECB.

`OracleBase::encrypt` gestisce la cifratura effettiva concatenando prefisso + input + suffisso, poi cifrando in CBC o ECB.

### Il test

```rust
#[test]
pub fn challenge_11() {
    let oracle = CustomCrypter11::new();
    match oracle {
        Ok(r) => {
            let input: Vec<u8> = vec![0; 48];
            let encrypted_value = r.base.encrypt(&input).unwrap();
            if r.is_cbc() {
                assert_eq!(r.is_ecb_calculated(encrypted_value).unwrap(), false);
            } else if r.is_ecb() {
                assert_eq!(r.is_ecb_calculated(encrypted_value).unwrap(), true);
            }
        }
        Err(_) => { panic!(); }
    }
}
```

L'input di 48 zeri garantisce blocchi ripetuti nel plaintext. Il test verifica che `is_ecb_calculated` concordi con la modalità reale dell'oracle.

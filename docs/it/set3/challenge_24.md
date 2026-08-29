---
layout: default
title: "Sfida 24 — Crea lo stream cipher MT19937 e rompilo"
parent: "Set 3 IT"
grand_parent: IT
nav_order: 8
permalink: /it/set3/challenge_24/
lang: it
---

# Sfida 24 — Crea lo stream cipher MT19937 e rompilo

[← Sfida precedente](../challenge_23/) · [🇬🇧 English](../../../en/set3/challenge_24/) · [Set 3](../) · [Home](../../)

---

## Teoria

La sfida 24 trasforma MT19937 in uno stream cipher: per una chiave `seed` a 16 bit, si genera un keystream chiamando ripetutamente `extract_number()` e prendendo i suoi `to_le_bytes()` (4 byte per output), poi si fa XOR tra keystream e plaintext. La decifratura è identica: `ciphertext XOR keystream = plaintext`. Il cifrario aggiunge anche un prefisso casuale di `5..20` byte casuali per nascondere l'allineamento.

Il cifrario viene rotto in due modi complementari, entrambi sfruttando il minuscolo spazio delle chiavi a 16 bit (`2^16 = 65536` candidati):

**Attacco a plaintext noto**: l'attaccante sa che il plaintext termina con `14` byte di `A` (`"AAAAAAAAAAAAAA"`). Per ogni seed candidato in `0..=65535`, l'attaccante decifra il ciphertext rigenerando il keystream da quel seed e verifica se il risultato termina con il suffisso noto. Solo il vero seed produce un plaintext con quel suffisso (con probabilità schiacciante).

**Attacco al token di reset password**: un token di reset viene generato come `MT19937::new(time_seed).extract_number()` dove `time_seed` è il timestamp corrente. Un attaccante che osserva il token e sa approssimativamente quando è stato generato può tentare i timestamp degli ultimi qualche centinaio di secondi, esattamente come nella sfida 22.

Entrambi gli attacchi dimostrano che MT19937 con un seed piccolo o prevedibile non offre alcuna sicurezza come stream cipher.

## Concetti chiave

- **Stream cipher MT19937**: `keystream = concat( MT19937(seed).extract_number().to_le_bytes() )`, `ciphertext = plaintext XOR keystream`.
- **Seed a 16 bit**: solo `65536` possibilità — banale da brute-forzare.
- **Prefisso casuale**: `prefix_len = rand(5..20)`, `prefix = random_block(prefix_len)` nasconde l'offset del plaintext noto ma non aggiunge sicurezza.
- **Suffisso noto**: `"AAAAAAAAAAAAAA"` (14 × `A`) è l'ancora per il check brute-force `candidate_plaintext.ends_with(known_plaintext)`.
- **Attacco al token**: `token = MT19937::new(now - delay).extract_number()`, brute-force `now-200..now`.
- **`MT19937::encrypt`**: metodo in `src/mt19937/mod.rs` che genera il keystream e fa XOR; `decrypt` è identico.
- **`USizeCrypt::random_block`**: genera i byte casuali del prefisso.

## Spiegazione del codice

### Struttura generale

Il modulo `src/mt19937/mod.rs` fornisce `MT19937::keystream` e `MT19937::encrypt`. Il test `src/set3.rs` (`challenge_24`) implementa sia il break a plaintext noto sia il break del token.

### Implementazione

Cifratura (simmetrica — la decifratura è identica):

```rust
pub fn keystream(&mut self, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let val = self.extract_number();
        for b in val.to_le_bytes().iter() {
            if out.len() < len { out.push(*b); }
        }
    }
    out
}

pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
    let ks = self.keystream(data.len());
    data.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect()
}
```

Brute-force a plaintext noto (dal test):

```rust
let seed: u16 = rng.gen();
let prefix: Vec<u8> = prefix_len.random_block();
let mut plaintext = Vec::new();
plaintext.extend_from_slice(&prefix);
plaintext.extend_from_slice(b"AAAAAAAAAAAAAA");
let mut mt_enc = MT19937::new(seed as u32);
let ciphertext = mt_enc.encrypt(&plaintext);

let mut cracked_seed: Option<u16> = None;
for candidate in 0u16..=u16::MAX {
    let mut mt_candidate = MT19937::new(candidate as u32);
    let candidate_plaintext = mt_candidate.encrypt(&ciphertext);
    if candidate_plaintext.ends_with(b"AAAAAAAAAAAAAA") {
        cracked_seed = Some(candidate);
        break;
    }
}
assert_eq!(cracked_seed.unwrap(), seed);
```

Brute-force del token:

```rust
let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
let token_seed = now - rng.gen_range(0..100);
let mut token_mt = MT19937::new(token_seed);
let token = token_mt.extract_number();
let mut token_found = None;
for i in 0..200 {
    let candidate = now - i;
    let mut test_mt = MT19937::new(candidate);
    if test_mt.extract_number() == token { token_found = Some(candidate); break; }
}
assert_eq!(token_found.unwrap(), token_seed);
```

### Il test

```rust
#[test]
pub fn challenge_24() {
    // seed casuale 16-bit + prefisso casuale + "AAAAAAAAAAAAAA" -> cifra -> brute force
    assert_eq!(cracked_seed.unwrap(), seed);
    assert_eq!(cracked_plaintext.unwrap(), plaintext);
    // round-trip: cifra poi decifra con stesso seed
    let mut dec = MT19937::new(seed2 as u32);
    assert_eq!(dec.encrypt(&ct), data);
    // verifica attacco al token
    assert_eq!(token_found.unwrap(), token_seed);
}
```

Verifica tre proprietà: lo stream cipher con chiave a 16 bit viene rotto con ricerca esaustiva usando il suffisso noto, la cifratura è reversibile con lo stesso seed, e un token di reset seeded col tempo è recuperabile facendo brute-force dei timestamp recenti.

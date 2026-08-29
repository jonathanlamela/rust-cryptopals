---
layout: default
title: "Sfida 22 — Cracca il seed di MT19937"
parent: "Set 3 IT"
grand_parent: IT
nav_order: 6
permalink: /it/set3/challenge_22/
lang: it
---

# Sfida 22 — Cracca il seed di MT19937

[← Sfida precedente](../challenge_21/) · [Sfida successiva →](../challenge_23/) · [🇬🇧 English](../../../en/set3/challenge_22/) · [Set 3](../) · [Home](../../)

---

## Teoria

MT19937 viene inizializzato (seeded) con un singolo intero a 32 bit. In molti usi errati nel mondo reale, il seed è il timestamp Unix corrente (`time(NULL)`). L'attacco della sfida 22 sfrutta il fatto che lo spazio dei seed è piccolo e prevedibile quando derivato dal tempo.

Lo scenario: l'applicazione attende un numero casuale di secondi (`40..1000`), inizializza MT19937 con il timestamp corrente, attende di nuovo, poi emette il primo numero casuale. Un attaccante che osserva l'output e conosce approssimativamente quando è stato generato può tentare tutti i timestamp del passato recente.

Il brute-force è banale perché lo spazio dei timestamp è minuscolo (poche migliaia di valori). Per ogni timestamp candidato, l'attaccante crea un MT19937 con quel seed e verifica se il primo output coincide con quello osservato. Il candidato che coincide è il vero seed. Questo dimostra perché MT19937 non deve mai essere inizializzato con valori prevedibili come i timestamp per scopi di sicurezza.

## Concetti chiave

- **Seed basato sul tempo**: `seed = now - wait1` dove `wait1` è un piccolo ritardo casuale.
- **Spazio di ricerca piccolo**: bastano ~2000 candidati quando il momento di generazione è approssimativamente noto.
- **Brute-force**: `for candidate in (now-2000)..now { if MT19937::new(candidate).extract_number() == observed }`.
- **`SystemTime` / `UNIX_EPOCH`**: standard library di Rust per ottenere `now` come `u32` in secondi.
- **`rand::thread_rng().gen_range(40..1000)`**: simula le attese casuali senza `sleep` reale.
- **PRNG non sicuro**: l'output di MT19937 è interamente determinato dal seed; recuperare il seed compromette tutti gli output futuri.

## Spiegazione del codice

### Struttura generale

La sfida è implementata interamente nel test `src/set3.rs` (`challenge_22`) usando `src/mt19937/mod.rs` (`MT19937::new`, `extract_number`) e `rand` per simulare le attese.

### Implementazione

Simula il seeding con un timestamp nel passato recente:

```rust
let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
let wait1: u32 = rng.gen_range(40..1000);
let seed = now - wait1;
let mut mt = MT19937::new(seed);
let first_output = mt.extract_number();
```

Brute-force del seed dal punto di vista dell'attaccante:

```rust
let mut cracked_seed: Option<u32> = None;
for i in 0..2000 {
    let candidate = now - i;
    let mut test_mt = MT19937::new(candidate);
    if test_mt.extract_number() == first_output {
        cracked_seed = Some(candidate);
        break;
    }
}
assert_eq!(cracked_seed.unwrap(), seed);
```

Il test esegue anche un secondo controllo generico con un seed casuale in `0..10000`, facendo brute-force su `0..20000` per dimostrare che la tecnica funziona anche fuori dallo scenario timestamp:

```rust
let random_seed: u32 = rng.gen_range(0..10000);
let mut mt2 = MT19937::new(random_seed);
let out2 = mt2.extract_number();
let mut found = None;
for candidate in 0..20000u32 {
    let mut test = MT19937::new(candidate);
    if test.extract_number() == out2 { found = Some(candidate); break; }
}
assert_eq!(found.unwrap(), random_seed);
```

### Il test

```rust
#[test]
pub fn challenge_22() {
    let mut rng = rand::thread_rng();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    let wait1: u32 = rng.gen_range(40..1000);
    let seed = now - wait1;
    let mut mt = MT19937::new(seed);
    let first_output = mt.extract_number();
    // brute force dei timestamp recenti...
    assert_eq!(cracked_seed.unwrap(), seed);
    // controllo generico aggiuntivo...
}
```

Verifica che un seed MT19937 derivato dal tempo possa essere recuperato cercando negli ultimi 2000 secondi, e che qualsiasi seed in un piccolo intervallo possa essere brute-forzato similmente.

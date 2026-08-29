---
layout: default
title: "Sfida 21 — Implementa il RNG MT19937 Mersenne Twister"
parent: "Set 3 IT"
grand_parent: IT
nav_order: 5
permalink: /it/set3/challenge_21/
lang: it
---

# Sfida 21 — Implementa il RNG MT19937 Mersenne Twister

[← Sfida precedente](../challenge_20/) · [Sfida successiva →](../challenge_22/) · [🇬🇧 English](../../../en/set3/challenge_21/) · [Set 3](../) · [Home](../../)

---

## Teoria

Il Mersenne Twister (MT19937) è uno dei generatori pseudo-casuali più diffusi. Progettato da Matsumoto e Nishimura nel 1997, ha un periodo di `2^19937 − 1` (un primo di Mersenne, da cui il nome) ed è il RNG di default in molti linguaggi tra cui `random` di Python, Ruby e PHP.

MT19937 opera su uno stato di 624 parole a 32 bit. Il cuore è la trasformazione **twist**: ogni parola viene combinata dal bit alto di `mt[i]` e dai 31 bit bassi di `mt[i+1]`, shiftata a destra di uno e condizionalmente XOR con la costante `MATRIX_A = 0x9908B0DF` se il valore combinato è dispari. Il risultato viene XOR con `mt[(i+397) % 624]`.

Il seeding usa una ricorrenza semplice: `mt[0] = seed`, `mt[i] = 1812433253 * (mt[i-1] ^ (mt[i-1] >> 30)) + i`. Dopo ogni twist i numeri vengono **temperati** per migliorare l'equidistribuzione: quattro XOR/shift/mask successivi con le costanti `U=11/D=0xFFFFFFFF`, `S=7/B=0x9D2C5680`, `T=15/C=0xEFC60000`, `L=18`.

MT19937 non è crittograficamente sicuro — osservare 624 output rivela l'intero stato interno — ma è eccellente per simulazioni ed è spesso usato erroneamente dove serve casualità crittografica.

## Concetti chiave

- **Periodo `2^19937−1`**: periodo enorme che rende praticamente impossibile la ripetizione della sequenza.
- **Array di stato**: 624 parole × 32 bit (`N=624`) twistate in blocco.
- **Twist**: `x = (mt[i] & UPPER_MASK) + (mt[i+1] & LOWER_MASK)`, `xA = x>>1 ^ (x&1 ? MATRIX_A : 0)`, `mt[i] = mt[i+397] ^ xA`.
- **Tempering**: `y ^= (y>>U)&D`, `y ^= (y<<S)&B`, `y ^= (y<<T)&C`, `y ^= y>>L`.
- **Seeding**: inizializzazione deterministica con moltiplicatore `F=1812433253`.
- **Struct `MT19937`**: implementazione in `src/mt19937/mod.rs` con `new`, `seed`, `extract_number`, `twist`.
- **Vettore di riferimento**: seed `5489` deve produrre `3499211612, 581869302, 3890346734, 3586334585, 545404204`.

## Spiegazione del codice

### Struttura generale

La sfida è implementata in `src/mt19937/mod.rs` come modulo autonomo, indipendente dall'AES di `cryptovec`. Viene poi testata in `src/set3.rs` (`challenge_21`). Il modulo fornisce anche gli helper `untemper` e `clone_mt19937` usati dalle sfide 23–24.

### Implementazione

Struttura e costanti:

```rust
const N: usize = 624;
const M: usize = 397;
const MATRIX_A: u32 = 0x9908B0DF;
const UPPER_MASK: u32 = 0x80000000;
const LOWER_MASK: u32 = 0x7FFFFFFF;
const F: u32 = 1812433253;

pub struct MT19937 {
    mt: [u32; N],
    index: usize,
}
```

Seeding:

```rust
pub fn new(seed: u32) -> Self {
    let mut mt = [0u32; N];
    mt[0] = seed;
    for i in 1..N {
        mt[i] = F.wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> 30)).wrapping_add(i as u32);
    }
    MT19937 { mt, index: N }
}
```

Twist ed estrazione:

```rust
fn twist(&mut self) {
    for i in 0..N {
        let x = (self.mt[i] & UPPER_MASK) + (self.mt[(i + 1) % N] & LOWER_MASK);
        let mut x_a = x >> 1;
        if x % 2 != 0 { x_a ^= MATRIX_A; }
        self.mt[i] = self.mt[(i + M) % N] ^ x_a;
    }
    self.index = 0;
}

pub fn extract_number(&mut self) -> u32 {
    if self.index >= N { self.twist(); }
    let mut y = self.mt[self.index];
    y ^= (y >> 11) & 0xFFFFFFFF;
    y ^= (y << 7) & 0x9D2C5680;
    y ^= (y << 15) & 0xEFC60000;
    y ^= y >> 18;
    self.index += 1;
    y
}
```

Helper keystream usato dalla sfida 24 (`to_le_bytes`):

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
```

### Il test

```rust
#[test]
pub fn challenge_21() {
    let mut mt = MT19937::new(5489);
    let expected = [3499211612u32, 581869302, 3890346734, 3586334585, 545404204];
    for &exp in &expected {
        assert_eq!(mt.extract_number(), exp);
    }
    // determinismo: stesso seed -> stessa sequenza
    let mut mt1 = MT19937::new(0);
    let mut mt2 = MT19937::new(0);
    for _ in 0..100 { assert_eq!(mt1.extract_number(), mt2.extract_number()); }
    // verifica round-trip di untemper
    let mut mt_check = MT19937::new(12345);
    for _ in 0..10 {
        let tempered = mt_check.extract_number();
        let recovered = untemper(tempered);
        let mut y = recovered;
        y ^= (y >> 11) & 0xFFFFFFFF;
        y ^= (y << 7) & 0x9D2C5680;
        y ^= (y << 15) & 0xEFC60000;
        y ^= y >> 18;
        assert_eq!(y, tempered);
    }
}
```

Il test verifica il vettore di riferimento per seed `5489`, il determinismo per seed `0`, e che `untemper` inverta correttamente la trasformazione di tempering.

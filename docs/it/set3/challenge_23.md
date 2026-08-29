---
layout: default
title: "Sfida 23 — Clona MT19937 dall'output"
parent: "Set 3 IT"
grand_parent: IT
nav_order: 7
permalink: /it/set3/challenge_23/
lang: it
---

# Sfida 23 — Clona MT19937 dall'output

[← Sfida precedente](../challenge_22/) · [Sfida successiva →](../challenge_24/) · [🇬🇧 English](../../../en/set3/challenge_23/) · [Set 3](../) · [Home](../../)

---

## Teoria

MT19937 non è crittograficamente sicuro perché la sua trasformazione di tempering è invertibile. Dati 624 output consecutivi, un attaccante può invertire il tempering per recuperare l'array di stato interno `mt[0..623]`, poi predire tutti gli output futuri.

Il tempering consiste in quattro operazioni invertibili:

```
y ^= (y >> U) & D   // U=11, D=0xFFFFFFFF
y ^= (y << S) & B   // S=7,  B=0x9D2C5680
y ^= (y << T) & C   // T=15, C=0xEFC60000
y ^=  y >> L        // L=18
```

Invertirle richiede ricostruzione bit per bit. Per `y ^= y >> shift` (senza mask), i bit vengono recuperati dal più significativo al meno significativo: i primi `shift` bit sono invariati, poi ogni bit successivo è `y[i] = tempered[i] ^ recovered[i+shift]`. Con una mask, la formula diventa `y[i] = tempered[i] ^ (recovered[i±shift] & mask[i])`. Invertendo in ordine inverso (`L`, `T`, `S`, `U`) si ottiene la parola di stato originale:

```
untemper(y) = undo_right(y, L)
            → undo_left(y, T, C)
            → undo_left(y, S, B)
            → undo_right(y, U, D)
```

Una volta recuperate le 624 parole di stato, l'attaccante costruisce un clone con `MT19937::from_state(state, 624)` e le sue successive chiamate a `extract_number()` saranno identiche a quelle dell'originale.

## Concetti chiave

- **Tempering invertibile**: ogni operazione di temper è uno XOR con una versione shiftata/mascherata di se stessa, quindi reversibile.
- **`untemper`**: funzione in `src/mt19937/mod.rs` che applica le quattro operazioni inverse in ordine inverso.
- **`undo_right_shift_xor` / `undo_left_shift_xor_mask`**: helper a livello di bit che ricostruiscono il valore originale.
- **`clone_mt19937`**: raccoglie 624 output untempered in un array di stato e costruisce un nuovo `MT19937::from_state(state, 624)`.
- **624 output = stato completo**: servono esattamente `N` output per ricostruire lo stato intero; meno output lasciano lo stato ambiguo.
- **Predizione**: gli output futuri del clone sono identici bit-per-bit a quelli dell'originale.

## Spiegazione del codice

### Struttura generale

La logica centrale è in `src/mt19937/mod.rs` (`untemper`, `clone_mt19937`, `MT19937::from_state`). Il test in `src/set3.rs` (`challenge_23`) verifica la clonazione con un seed casuale e con il seed noto `0`.

### Implementazione

Helper untemper (esempio right shift senza mask):

```rust
fn undo_right_shift_xor(value: u32, shift: u32) -> u32 {
    let mut result = 0u32;
    for i in (0..32).rev() {
        let bit = (value >> i) & 1;
        if i + shift as usize >= 32 {
            result |= bit << i;
        } else {
            let known_bit = (result >> (i + shift as usize)) & 1;
            result |= (bit ^ known_bit) << i;
        }
    }
    result
}
```

Inverso completo:

```rust
pub fn untemper(y: u32) -> u32 {
    let mut v = y;
    v = undo_right_shift_xor(v, L);
    v = undo_left_shift_xor_mask(v, T, C);
    v = undo_left_shift_xor_mask(v, S, B);
    v = undo_right_shift_xor_mask(v, U, D);
    v
}

pub fn clone_mt19937(outputs: &[u32]) -> MT19937 {
    assert!(outputs.len() >= 624);
    let mut state = [0u32; 624];
    for i in 0..624 { state[i] = untemper(outputs[i]); }
    MT19937::from_state(state, 624)
}
```

### Il test

```rust
#[test]
pub fn challenge_23() {
    let mut rng = rand::thread_rng();
    let seed: u32 = rng.gen();
    let mut original = MT19937::new(seed);
    let mut outputs = Vec::new();
    for _ in 0..624 { outputs.push(original.extract_number()); }
    let mut cloned = clone_mt19937(&outputs);
    for _ in 0..100 {
        assert_eq!(cloned.extract_number(), original.extract_number());
    }
    // check deterministico con seed 0
    let mut mt_known = MT19937::new(0);
    let mut known_outputs = Vec::new();
    for _ in 0..624 { known_outputs.push(mt_known.extract_number()); }
    let mut cloned_known = clone_mt19937(&known_outputs);
    for _ in 0..10 { assert_eq!(mt_known.extract_number(), cloned_known.extract_number()); }
}
```

Raccoglie 624 output da un MT19937 con seed casuale, clona tramite `untemper`, e asserisce che le successive 100 predizioni coincidano esattamente. Un secondo check con seed `0` garantisce la clonazione deterministica.

---
layout: default
title: "Challenge 23 — Clone an MT19937 from its output"
parent: "Set 3 EN"
grand_parent: EN
nav_order: 7
permalink: /en/set3/challenge_23/
lang: en
---

# Challenge 23 — Clone an MT19937 from its output

[← Previous](../challenge_22/) · [Next →](../challenge_24/) · [🇮🇹 Italiano](../../../it/set3/challenge_23/) · [Set 3](../) · [Home](../../)

---

## Theory

MT19937 is not cryptographically secure because its tempering transformation is invertible. Given 624 consecutive outputs, an attacker can reverse the tempering to recover the internal state array `mt[0..623]`, then predict all future outputs.

Tempering consists of four invertible operations:

```
y ^= (y >> U) & D   // U=11, D=0xFFFFFFFF
y ^= (y << S) & B   // S=7,  B=0x9D2C5680
y ^= (y << T) & C   // T=15, C=0xEFC60000
y ^=  y >> L        // L=18
```

Inverting them requires bit-by-bit reconstruction. For `y ^= y >> shift` (no mask), bits are recovered from most significant to least significant: the top `shift` bits are unchanged, then each subsequent bit is `y[i] = tempered[i] ^ recovered[i+shift]`. With a mask, the formula becomes `y[i] = tempered[i] ^ (recovered[i±shift] & mask[i])`. Inverting in reverse order (`L`, `T`, `S`, `U`) yields the original untempered state word:

```
untemper(y) = undo_right(y, L)
            → undo_left(y, T, C)
            → undo_left(y, S, B)
            → undo_right(y, U, D)
```

Once the 624 state words are recovered, the attacker constructs a clone with `MT19937::from_state(state, 624)` and its next `extract_number()` calls are identical to the original's.

## Key concepts

- **Invertible tempering**: every temper operation is an XOR with a shifted/masked version of itself, hence reversible.
- **`untemper`**: `src/mt19937/mod.rs` function applying the four inverse operations in reverse order.
- **`undo_right_shift_xor` / `undo_left_shift_xor_mask`**: bit-level helpers reconstructing the original value.
- **`clone_mt19937`**: collects 624 untempered outputs into a state array and builds a new `MT19937::from_state(state, 624)`.
- **624 outputs = full state**: exactly `N` outputs are needed to reconstruct the complete state; fewer outputs leave the state ambiguous.
- **Prediction**: cloned RNG's future outputs are bit-for-bit identical to the original's.

## Code walkthrough

### Overview

The core logic is in `src/mt19937/mod.rs` (`untemper`, `clone_mt19937`, `MT19937::from_state`). The test in `src/set3.rs` (`challenge_23`) exercises cloning with a random seed and with the known seed `0`.

### Implementation

Untemper helpers (right shift example without mask):

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

Full inverse:

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

### The test

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
    // deterministic check with seed 0
    let mut mt_known = MT19937::new(0);
    let mut known_outputs = Vec::new();
    for _ in 0..624 { known_outputs.push(mt_known.extract_number()); }
    let mut cloned_known = clone_mt19937(&known_outputs);
    for _ in 0..10 { assert_eq!(mt_known.extract_number(), cloned_known.extract_number()); }
}
```

Collects 624 outputs from a randomly seeded MT19937, clones via `untemper`, and asserts the next 100 predictions match exactly. A second check with seed `0` ensures deterministic cloning.

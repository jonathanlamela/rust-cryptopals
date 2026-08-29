---
layout: default
title: "Challenge 21 — Implement the MT19937 Mersenne Twister RNG"
parent: "Set 3 EN"
grand_parent: EN
nav_order: 5
permalink: /en/set3/challenge_21/
lang: en
---

# Challenge 21 — Implement the MT19937 Mersenne Twister RNG

[← Previous](../challenge_20/) · [Next →](../challenge_22/) · [🇮🇹 Italiano](../../../it/set3/challenge_21/) · [Set 3](../) · [Home](../../)

---

## Theory

The Mersenne Twister (MT19937) is one of the most widely used pseudo-random number generators. Designed by Matsumoto and Nishimura in 1997, it has a period of `2^19937 − 1` (a Mersenne prime, hence the name) and is the default RNG in many languages including Python's `random`, Ruby, and PHP.

MT19937 operates on a state of 624 32-bit words. The core is the **twist** transformation: each word is combined from the upper bit of `mt[i]` and the lower 31 bits of `mt[i+1]`, shifted right by one, and conditionally XORed with the constant `MATRIX_A = 0x9908B0DF` if the combined value is odd. The result is XORed with `mt[(i+397) % 624]`.

Seeding uses a simple recurrence: `mt[0] = seed`, `mt[i] = 1812433253 * (mt[i-1] ^ (mt[i-1] >> 30)) + i`. After each twist, numbers are **tempered** to improve equidistribution: four successive XOR/shift/mask operations with constants `U=11/D=0xFFFFFFFF`, `S=7/B=0x9D2C5680`, `T=15/C=0xEFC60000`, `L=18`.

MT19937 is not cryptographically secure — observing 624 outputs reveals the entire internal state — but it is excellent for simulations and is often mistakenly used where cryptographic randomness is needed.

## Key concepts

- **Period `2^19937−1`**: enormous period making sequence repetition practically impossible.
- **State array**: 624 × 32-bit words (`N=624`) that are twisted as a batch.
- **Twist**: `x = (mt[i] & UPPER_MASK) + (mt[i+1] & LOWER_MASK)`, `xA = x>>1 ^ (x&1 ? MATRIX_A : 0)`, `mt[i] = mt[i+397] ^ xA`.
- **Tempering**: `y ^= (y>>U)&D`, `y ^= (y<<S)&B`, `y ^= (y<<T)&C`, `y ^= y>>L`.
- **Seeding**: deterministic initialization with `F=1812433253` multiplier.
- **`MT19937` struct**: `src/mt19937/mod.rs` implementation with `new`, `seed`, `extract_number`, `twist`.
- **Reference vector**: seed `5489` must produce `3499211612, 581869302, 3890346734, 3586334585, 545404204`.

## Code walkthrough

### Overview

The challenge is implemented in `src/mt19937/mod.rs` as a standalone module, independent of the AES-based `cryptovec`. It is then tested in `src/set3.rs` (`challenge_21`). The module also provides `untemper` and `clone_mt19937` helpers used by challenges 23–24.

### Implementation

Core structure and constants:

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

Twist and extraction:

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

Keystream helper used by challenge 24 (`to_le_bytes`):

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

### The test

```rust
#[test]
pub fn challenge_21() {
    let mut mt = MT19937::new(5489);
    let expected = [3499211612u32, 581869302, 3890346734, 3586334585, 545404204];
    for &exp in &expected {
        assert_eq!(mt.extract_number(), exp);
    }
    // determinism: same seed -> same sequence
    let mut mt1 = MT19937::new(0);
    let mut mt2 = MT19937::new(0);
    for _ in 0..100 { assert_eq!(mt1.extract_number(), mt2.extract_number()); }
    // untemper round-trip verification
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

The test verifies the reference vector for seed `5489`, determinism for seed `0`, and that `untemper` correctly inverts the tempering transformation.

---
layout: default
title: "Challenge 22 — Crack an MT19937 seed"
parent: "Set 3 EN"
grand_parent: EN
nav_order: 6
permalink: /en/set3/challenge_22/
lang: en
---

# Challenge 22 — Crack an MT19937 seed

[← Previous](../challenge_21/) · [Next →](../challenge_23/) · [🇮🇹 Italiano](../../../it/set3/challenge_22/) · [Set 3](../) · [Home](../../)

---

## Theory

MT19937 is seeded with a single 32-bit integer. In many real-world misuses, the seed is the current Unix timestamp (`time(NULL)`). The attack in challenge 22 exploits the fact that the seed space is small and predictable when the seed is time-derived.

The scenario: the application waits a random number of seconds (`40..1000`), seeds MT19937 with the current timestamp, waits again, then outputs the first random number. An attacker who observes the output and knows approximately when it was generated can brute-force the seed by trying all timestamps in the recent past.

The brute-force is trivial because the timestamp space is tiny (a few thousand values). For each candidate timestamp, the attacker creates an MT19937 with that seed and checks whether the first output matches the observed one. The matching candidate is the true seed. This demonstrates why MT19937 must never be seeded with predictable values like timestamps for security purposes.

## Key concepts

- **Time-based seed**: `seed = now - wait1` where `wait1` is a small random delay.
- **Small search space**: only ~2000 candidates needed when the generation time is approximately known.
- **Brute-force**: `for candidate in (now-2000)..now { if MT19937::new(candidate).extract_number() == observed }`.
- **`SystemTime` / `UNIX_EPOCH`**: Rust standard library to obtain `now` as `u32` seconds.
- **`rand::thread_rng().gen_range(40..1000)`**: simulates the random waits without actual `sleep`.
- **Non-secure PRNG**: MT19937 output is fully determined by the seed; recovering the seed compromises all future outputs.

## Code walkthrough

### Overview

The challenge is implemented entirely in the test `src/set3.rs` (`challenge_22`) using `src/mt19937/mod.rs` (`MT19937::new`, `extract_number`) and `rand` for simulating waits.

### Implementation

Simulate seeding with a timestamp in the recent past:

```rust
let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
let wait1: u32 = rng.gen_range(40..1000);
let seed = now - wait1;
let mut mt = MT19937::new(seed);
let first_output = mt.extract_number();
```

Brute-force the seed from the attacker's perspective:

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

The test also performs a second generic check with a random seed in `0..10000`, brute-forcing `0..20000` to prove the technique works outside the timestamp scenario:

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

### The test

```rust
#[test]
pub fn challenge_22() {
    let mut rng = rand::thread_rng();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    let wait1: u32 = rng.gen_range(40..1000);
    let seed = now - wait1;
    let mut mt = MT19937::new(seed);
    let first_output = mt.extract_number();
    // brute force recent timestamps...
    assert_eq!(cracked_seed.unwrap(), seed);
    // additional generic brute force...
}
```

Verifies that a time-derived MT19937 seed can be recovered by searching the last 2000 seconds, and that any seed in a small range can be brute-forced similarly.

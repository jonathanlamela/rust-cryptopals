---
layout: default
title: "Challenge 24 — Create the MT19937 stream cipher and break it"
parent: "Set 3 EN"
grand_parent: EN
nav_order: 8
permalink: /en/set3/challenge_24/
lang: en
---

# Challenge 24 — Create the MT19937 stream cipher and break it

[← Previous](../challenge_23/) · [🇬🇧 Italiano](../../../it/set3/challenge_24/) · [Set 3](../) · [Home](../../)

---

## Theory

Challenge 24 turns MT19937 into a stream cipher: for a 16-bit key `seed`, generate a keystream by repeatedly calling `extract_number()` and taking its `to_le_bytes()` (4 bytes per output), then XOR the keystream with the plaintext. Decryption is identical: `ciphertext XOR keystream = plaintext`. The cipher also prepends a random prefix of `5..20` random bytes to hide alignment.

The cipher is broken in two complementary ways, both exploiting the tiny 16-bit keyspace (`2^16 = 65536` candidates):

**Known-plaintext attack**: The attacker knows the plaintext ends with `14` bytes of `A` (`"AAAAAAAAAAAAAA"`). For each candidate seed in `0..=65535`, the attacker decrypts the ciphertext by regenerating the keystream from that seed and checks whether the result ends with the known suffix. Only the true seed produces a plaintext with that suffix (with overwhelming probability).

**Password reset token attack**: A reset token is generated as `MT19937::new(time_seed).extract_number()` where `time_seed` is the current timestamp. An attacker who observes the token and knows approximately when it was generated can brute-force timestamps in the last few hundred seconds, exactly as in challenge 22.

Both attacks demonstrate that MT19937 with a small or predictable seed offers no security as a stream cipher.

## Key concepts

- **MT19937 stream cipher**: `keystream = concat( MT19937(seed).extract_number().to_le_bytes() )`, `ciphertext = plaintext XOR keystream`.
- **16-bit seed**: only `65536` possibilities — trivial to brute-force.
- **Random prefix**: `prefix_len = rand(5..20)`, `prefix = random_block(prefix_len)` hides the known plaintext offset but does not add security.
- **Known suffix**: `"AAAAAAAAAAAAAA"` (14 × `A`) is the anchor for the brute-force check `candidate_plaintext.ends_with(known_plaintext)`.
- **Token attack**: `token = MT19937::new(now - delay).extract_number()`, brute-force `now-200..now`.
- **`MT19937::encrypt`**: `src/mt19937/mod.rs` method generating keystream and XORing; `decrypt` is identical.
- **`USizeCrypt::random_block`**: generates random prefix bytes.

## Code walkthrough

### Overview

The module `src/mt19937/mod.rs` provides `MT19937::keystream` and `MT19937::encrypt`. The test `src/set3.rs` (`challenge_24`) implements both the known-plaintext break and the token break.

### Implementation

Encryption (symmetric — decrypt is the same):

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

Known-plaintext brute-force (from the test):

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

Token brute-force:

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

### The test

```rust
#[test]
pub fn challenge_24() {
    // random 16-bit seed + random prefix + "AAAAAAAAAAAAAA" -> encrypt -> brute force
    assert_eq!(cracked_seed.unwrap(), seed);
    assert_eq!(cracked_plaintext.unwrap(), plaintext);
    // round-trip: encrypt then decrypt with same seed
    let mut dec = MT19937::new(seed2 as u32);
    assert_eq!(dec.encrypt(&ct), data);
    // token attack verification
    assert_eq!(token_found.unwrap(), token_seed);
}
```

Verifies three properties: the 16-bit keystream cipher is broken by exhaustive search using the known suffix, encryption is reversible with the same seed, and a time-seeded reset token is recoverable by brute-forcing recent timestamps.

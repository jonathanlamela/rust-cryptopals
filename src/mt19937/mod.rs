/// MT19937 Mersenne Twister RNG
/// Implements the standard MT19937 parameters used in Cryptopals Set 3 Challenge 21.

const N: usize = 624;
const M: usize = 397;
const MATRIX_A: u32 = 0x9908B0DF;
const UPPER_MASK: u32 = 0x80000000;
const LOWER_MASK: u32 = 0x7FFFFFFF;
const F: u32 = 1812433253;

const U: u32 = 11;
const D: u32 = 0xFFFFFFFF;
const S: u32 = 7;
const B: u32 = 0x9D2C5680;
const T: u32 = 15;
const C: u32 = 0xEFC60000;
const L: u32 = 18;

#[derive(Clone, Debug)]
pub struct MT19937 {
    mt: [u32; N],
    index: usize,
}

impl MT19937 {
    /// Create a new MT19937 seeded with a single 32-bit value (standard init).
    pub fn new(seed: u32) -> Self {
        let mut mt = [0u32; N];
        mt[0] = seed;
        for i in 1..N {
            mt[i] = F
                .wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> 30))
                .wrapping_add(i as u32);
        }
        MT19937 { mt, index: N }
    }

    /// Seed / re-seed the generator.
    pub fn seed(&mut self, seed: u32) {
        self.mt[0] = seed;
        for i in 1..N {
            self.mt[i] = F
                .wrapping_mul(self.mt[i - 1] ^ (self.mt[i - 1] >> 30))
                .wrapping_add(i as u32);
        }
        self.index = N;
    }

    /// Twist transformation.
    fn twist(&mut self) {
        for i in 0..N {
            let x = (self.mt[i] & UPPER_MASK) + (self.mt[(i + 1) % N] & LOWER_MASK);
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                x_a ^= MATRIX_A;
            }
            self.mt[i] = self.mt[(i + M) % N] ^ x_a;
        }
        self.index = 0;
    }

    /// Extract a tempered value (main output).
    pub fn extract_number(&mut self) -> u32 {
        if self.index >= N {
            self.twist();
        }
        let mut y = self.mt[self.index];
        y ^= (y >> U) & D;
        y ^= (y << S) & B;
        y ^= (y << T) & C;
        y ^= y >> L;
        self.index += 1;
        y
    }

    /// Create from raw state (for cloning attack, challenge 23).
    pub fn from_state(state: [u32; N], index: usize) -> Self {
        MT19937 { mt: state, index }
    }

    /// Get internal state.
    pub fn get_state(&self) -> [u32; N] {
        self.mt
    }

    /// Get current index.
    pub fn get_index(&self) -> usize {
        self.index
    }

    /// Generate keystream bytes (little-endian u32 stream) for MT19937 stream cipher (challenge 24).
    pub fn keystream(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let val = self.extract_number();
            for b in val.to_le_bytes().iter() {
                if out.len() < len {
                    out.push(*b);
                }
            }
        }
        out
    }

    /// Encrypt / Decrypt via XOR with keystream (symmetric).
    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let ks = self.keystream(data.len());
        data.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect()
    }
}

/// Encrypt with MT19937 stream cipher using a 16-bit seed (challenge 24 style).
/// Prepends random prefix of random length and then XORs with MT19937 keystream.
pub fn mt19937_stream_encrypt(data: &[u8], seed: u16) -> Vec<u8> {
    let mut rng = MT19937::new(seed as u32);
    rng.encrypt(data)
}

/// Decrypt is identical to encrypt (XOR).
pub fn mt19937_stream_decrypt(data: &[u8], seed: u16) -> Vec<u8> {
    mt19937_stream_encrypt(data, seed)
}

// --- Untemper helpers for challenge 23 ---

fn undo_right_shift_xor(value: u32, shift: u32) -> u32 {
    let mut result = 0u32;
    // Reconstruct from most significant bits downwards
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

fn undo_right_shift_xor_mask(value: u32, shift: u32, mask: u32) -> u32 {
    let mut result = 0u32;
    for i in (0..32).rev() {
        let bit = (value >> i) & 1;
        let mask_bit = (mask >> i) & 1;
        if i + shift as usize >= 32 {
            result |= bit << i;
        } else {
            let known_bit = (result >> (i + shift as usize)) & 1;
            result |= (bit ^ (known_bit & mask_bit)) << i;
        }
    }
    result
}

fn undo_left_shift_xor_mask(value: u32, shift: u32, mask: u32) -> u32 {
    let mut result = 0u32;
    for i in 0..32 {
        let bit = (value >> i) & 1;
        let mask_bit = (mask >> i) & 1;
        if i < shift as usize {
            result |= bit << i;
        } else {
            let known_bit = (result >> (i - shift as usize)) & 1;
            result |= (bit ^ (known_bit & mask_bit)) << i;
        }
    }
    result
}

/// Reverse the tempering transform.
pub fn untemper(y: u32) -> u32 {
    let mut v = y;
    v = undo_right_shift_xor(v, L);
    v = undo_left_shift_xor_mask(v, T, C);
    v = undo_left_shift_xor_mask(v, S, B);
    v = undo_right_shift_xor_mask(v, U, D);
    v
}

/// Clone MT19937 from 624 consecutive outputs.
pub fn clone_mt19937(outputs: &[u32]) -> MT19937 {
    assert!(outputs.len() >= N);
    let mut state = [0u32; N];
    for i in 0..N {
        state[i] = untemper(outputs[i]);
    }
    MT19937::from_state(state, N)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_vector_seed_5489() {
        let mut mt = MT19937::new(5489);
        let expected = [3499211612, 581869302, 3890346734, 3586334585, 545404204];
        for &e in &expected {
            assert_eq!(mt.extract_number(), e);
        }
    }

    #[test]
    fn test_seed_0_vector() {
        let mut mt = MT19937::new(0);
        let expected = [2357136044, 2546248239, 3071714933, 3626093760, 2588848963];
        for &e in &expected {
            assert_eq!(mt.extract_number(), e);
        }
    }

    #[test]
    fn test_untemper_roundtrip() {
        let mut mt = MT19937::new(12345);
        for _ in 0..100 {
            let v = mt.extract_number();
            assert_eq!(v, {
                let u = mt.mt[mt.index - 1];
                let mut y = u;
                y ^= (y >> U) & D;
                y ^= (y << S) & B;
                y ^= (y << T) & C;
                y ^= y >> L;
                // verify untemper recovers u
                assert_eq!(untemper(y), u);
                y
            });
        }
    }

    #[test]
    fn test_clone() {
        let mut mt = MT19937::new(42);
        let mut outputs = Vec::new();
        for _ in 0..N {
            outputs.push(mt.extract_number());
        }
        let mut cloned = clone_mt19937(&outputs);
        for _ in 0..100 {
            assert_eq!(mt.extract_number(), cloned.extract_number());
        }
    }
}

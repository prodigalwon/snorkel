use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

const MAX_HASHES: usize = 8;

pub struct Bloom {
    bits: Vec<u64>,
    num_bits: u64,
    num_hashes: u32,
}

impl Bloom {
    pub fn new(num_bits: u64, num_hashes: u32) -> Self {
        let effective_bits = num_bits.max(64);
        let num_u64s = usize::try_from(effective_bits.saturating_add(63) / 64).unwrap_or(1);
        Self {
            bits: vec![0_u64; num_u64s.max(1)],
            num_bits: effective_bits,
            num_hashes: num_hashes.max(1).min(MAX_HASHES as u32),
        }
    }

    fn hash64(key: &[u8]) -> u64 {
        let mut h = DefaultHasher::new();
        key.hash(&mut h);
        h.finish()
    }

    fn positions(&self, key: &[u8]) -> [u64; MAX_HASHES] {
        let h = Self::hash64(key);
        let h1 = h & 0xFFFFFFFF_u64;
        let h2 = h >> 32;
        let mut out = [0_u64; MAX_HASHES];
        let n = self.num_hashes as usize;
        for (i, slot) in out.iter_mut().enumerate().take(n) {
            let i64 = i as u64;
            *slot = h1.wrapping_add(i64.wrapping_mul(h2)) % self.num_bits;
        }
        out
    }

    pub fn check(&self, key: &[u8]) -> bool {
        let positions = self.positions(key);
        let n = self.num_hashes as usize;
        for pos in positions.iter().take(n) {
            let idx = usize::try_from(pos / 64).unwrap_or(0);
            let bit = pos % 64;
            let Some(word) = self.bits.get(idx) else {
                return false;
            };
            if (word & (1_u64 << bit)) == 0 {
                return false;
            }
        }
        true
    }

    pub fn set(&mut self, key: &[u8]) {
        let positions = self.positions(key);
        let n = self.num_hashes as usize;
        for pos in positions.iter().take(n) {
            let idx = usize::try_from(pos / 64).unwrap_or(0);
            let bit = pos % 64;
            if let Some(word) = self.bits.get_mut(idx) {
                *word |= 1_u64 << bit;
            }
        }
    }

    pub fn clear(&mut self) {
        for word in self.bits.iter_mut() {
            *word = 0;
        }
    }
}

pub struct DoubleBloom {
    primary: Bloom,
    secondary: Bloom,
    primary_count: u64,
    saturation_count: u64,
}

impl DoubleBloom {
    pub fn new(num_bits: u64, num_hashes: u32, saturation_count: u64) -> Self {
        Self {
            primary: Bloom::new(num_bits, num_hashes),
            secondary: Bloom::new(num_bits, num_hashes),
            primary_count: 0,
            saturation_count,
        }
    }

    pub fn check(&self, key: &[u8]) -> bool {
        self.primary.check(key) || self.secondary.check(key)
    }

    pub fn set(&mut self, key: &[u8]) {
        self.primary.set(key);
        self.primary_count = self.primary_count.saturating_add(1);
        if self.primary_count >= self.saturation_count {
            std::mem::swap(&mut self.primary, &mut self.secondary);
            self.secondary.clear();
            self.primary_count = 0;
        }
    }
}

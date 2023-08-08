use std::sync::atomic::{AtomicU64, Ordering};

pub struct Window<const L: usize, const MAX: u64>([AtomicU64; L]);

impl<const L: usize, const MAX: u64> Window<L, MAX> {
    pub fn new() -> Self {
        Self(std::array::from_fn(|_| AtomicU64::new(0)))
    }
    /// Check the window without mutating state.
    pub fn check(&self, counter: u64) -> bool {
        let slot = &self.0[(counter as usize) % self.0.len()];
        let counter = counter.wrapping_add(1);
        let prev_counter = slot.load(Ordering::Relaxed);
        prev_counter < counter && counter.wrapping_sub(prev_counter) <= MAX
    }
    /// Update the window, returning true if the packet is still valid.
    /// This should only be called after the packet is authenticated.
    pub fn update(&self, counter: u64) -> bool {
        let slot = &self.0[(counter as usize) % self.0.len()];
        let counter = counter.wrapping_add(1);
        let prev_counter = slot.fetch_max(counter, Ordering::Relaxed);
        prev_counter < counter && counter.wrapping_sub(prev_counter) <= MAX
    }
}

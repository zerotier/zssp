use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use parking_lot::RwLock;

use crate::zeta::StateB2;
use crate::{application::CryptoLayer, proto::MAX_UNASSOCIATED_HANDSHAKE_STATES};

pub(crate) struct UnassociatedHandshakeCache<Application: CryptoLayer> {
    has_pending: AtomicBool, // Allowed to be falsely positive
    cache: RwLock<CacheInner<Application>>,
}
/// SoA format
struct CacheInner<C: CryptoLayer> {
    local_ids: [Option<NonZeroU32>; MAX_UNASSOCIATED_HANDSHAKE_STATES],
    expiries: [i64; MAX_UNASSOCIATED_HANDSHAKE_STATES],
    handshakes: [Option<Arc<StateB2<C>>>; MAX_UNASSOCIATED_HANDSHAKE_STATES],
}

/// Linear-search cache for capping the memory consumption of handshake data.
/// Designed specifically to have short and simple code that clearly bounds above
/// memory consumption.
impl<Application: CryptoLayer> UnassociatedHandshakeCache<Application> {
    pub(crate) fn new() -> Self {
        Self {
            has_pending: AtomicBool::new(false),
            cache: RwLock::new(CacheInner {
                local_ids: std::array::from_fn(|_| None),
                expiries: std::array::from_fn(|_| 0),
                handshakes: std::array::from_fn(|_| None),
            }),
        }
    }
    pub(crate) fn get(&self, local_id: NonZeroU32) -> Option<Arc<StateB2<Application>>> {
        let cache = self.cache.read();
        for (i, id) in cache.local_ids.iter().enumerate() {
            if *id == Some(local_id) {
                return cache.handshakes[i].clone();
            }
        }
        None
    }
    /// Returns the timestamp at which `service` should be called again, or `None` if there is no update.
    pub(crate) fn insert(
        &self,
        local_id: NonZeroU32,
        state: Arc<StateB2<Application>>,
        current_time: i64,
    ) -> Option<i64> {
        let mut cache = self.cache.write();
        let mut idx = 0;
        for i in 0..cache.local_ids.len() {
            if cache.local_ids[i].is_none() || cache.expiries[i] <= current_time {
                idx = i;
                break;
            } else if cache.local_ids[i] == Some(local_id) {
                return None;
            }
        }
        let expiry = current_time + Application::SETTINGS.fragment_assembly_timeout as i64;
        cache.local_ids[idx] = Some(local_id);
        cache.expiries[idx] = expiry;
        cache.handshakes[idx] = Some(state);
        self.has_pending.store(true, Ordering::Release);
        Some(expiry)
    }
    pub(crate) fn remove(&self, local_id: NonZeroU32) -> bool {
        let mut cache = self.cache.write();
        for (i, id) in cache.local_ids.iter().enumerate() {
            if *id == Some(local_id) {
                cache.local_ids[i] = None;
                cache.expiries[i] = 0;
                cache.handshakes[i] = None;
                return true;
            }
        }
        false
    }
    /// Returns the timestamp at which this function should be called again.
    pub(crate) fn service(&self, current_time: i64) -> i64 {
        // Only check for expiration if we have a pending packet.
        // This check is allowed to have false positives for simplicity's sake.
        let mut next_service_time = i64::MAX;
        if self.has_pending.swap(false, Ordering::Acquire) {
            // Check for packet expiration
            let mut cache = self.cache.write();
            for i in 0..cache.local_ids.len() {
                if cache.local_ids[i].is_some() {
                    let expiry = cache.expiries[i];
                    if expiry <= current_time {
                        cache.local_ids[i] = None;
                        cache.expiries[i] = 0;
                        cache.handshakes[i] = None;
                    } else {
                        next_service_time = next_service_time.min(expiry);
                    }
                }
            }
            if next_service_time < i64::MAX {
                self.has_pending.store(true, Ordering::Release);
            }
        }
        next_service_time
    }
}

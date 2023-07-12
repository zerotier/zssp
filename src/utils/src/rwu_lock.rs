use std::{
    ops::{Deref, DerefMut},
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
};

/// A wrapper around a `std::sync::RwLock` that allows for atomic upgrades of read locks to write locks.
/// This wrapped struct does not check for lock poisoning. It is assumed that the user will never allow a lock to become poisoned.
///
/// See the documentation of `std::sync::RwLock` for more details.
pub struct RwuLock<T>(RwLock<(usize, T)>);

impl<T> RwuLock<T> {
    pub fn new(t: T) -> Self {
        Self(RwLock::new((0, t)))
    }
    pub fn read<'a>(&'a self) -> RwuLockReadGuard<'a, T> {
        RwuLockReadGuard(self.0.read().unwrap())
    }
    pub fn write<'a>(&'a self) -> RwuLockWriteGuard<'a, T> {
        let mut w = self.0.write().unwrap();
        w.0 = w.0.wrapping_add(1);
        RwuLockWriteGuard(w)
    }

    pub fn upgrade<'a, 'b>(&'a self, r: RwuLockReadGuard<'b, T>) -> Option<RwuLockWriteGuard<'a, T>> {
        let write_id = r.0 .0;
        drop(r);
        let mut w = self.0.write().unwrap();
        if w.0 == write_id {
            w.0 = w.0.wrapping_add(1);
            Some(RwuLockWriteGuard(w))
        } else {
            None
        }
    }
}

/// RAII structure used to release the shared read access of a lock when dropped.
/// Can be atomically upgraded to a `RwuLockWriteGuard` with `RwuLock::upgrade`.
pub struct RwuLockReadGuard<'a, T>(RwLockReadGuard<'a, (usize, T)>);

impl<'a, T> Deref for RwuLockReadGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0 .1
    }
}
/// RAII structure used to release the exclusive write access of a lock when dropped.
pub struct RwuLockWriteGuard<'a, T>(RwLockWriteGuard<'a, (usize, T)>);

impl<'a, T> Deref for RwuLockWriteGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0 .1
    }
}
impl<'a, T> DerefMut for RwuLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0 .1
    }
}

use std::borrow::Borrow;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::Arc;

/// Wrapper around an Arc<T> that causes it to hash and compare (equality) by its pointer identity.
///
/// This can be used as e.g. a key in a HashMap to index by concrete object identity rather than the
/// value of the object contained in Arc<>.
#[repr(transparent)]
pub struct CanonicalArc<T>(Arc<T>);

impl<T> CanonicalArc<T> {
    #[inline(always)]
    pub fn cast_arc_ref(r: &Arc<T>) -> &Self {
        // Should be safe since this is #[repr(transparent)]
        debug_assert_eq!(std::mem::size_of::<CanonicalArc<T>>(), std::mem::size_of::<Arc<T>>());
        unsafe { std::mem::transmute(r) }
    }
}

impl<T> Hash for CanonicalArc<T> {
    #[inline(always)]
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state)
    }
}

impl<T> PartialEq for CanonicalArc<T> {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl<T> Eq for CanonicalArc<T> {}

impl<T> AsRef<Arc<T>> for CanonicalArc<T> {
    #[inline(always)]
    fn as_ref(&self) -> &Arc<T> {
        &self.0
    }
}

impl<T> Deref for CanonicalArc<T> {
    type Target = Arc<T>;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> From<Arc<T>> for CanonicalArc<T> {
    #[inline(always)]
    fn from(value: Arc<T>) -> Self {
        Self(value)
    }
}

impl<T> From<CanonicalArc<T>> for Arc<T> {
    #[inline(always)]
    fn from(value: CanonicalArc<T>) -> Self {
        value.0
    }
}

impl<T> Clone for CanonicalArc<T> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Borrow<Arc<T>> for CanonicalArc<T> {
    #[inline(always)]
    fn borrow(&self) -> &Arc<T> {
        &self.0
    }
}

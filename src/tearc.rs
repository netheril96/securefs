use std::{ops::Deref, pin::Pin, sync::Arc};

trait Erased {}

impl<T> Erased for T {}

// An Arc with destructor type erased, so it can be converted to ptr to
// subobjects.
pub struct Tearc<T: 'static> {
    storage: Pin<Arc<dyn Erased>>,
    pointer: *const T,
}

unsafe impl<T: Send + Sync + 'static> Send for Tearc<T> {}
unsafe impl<T: Send + Sync + 'static> Sync for Tearc<T> {}

impl<T: 'static> Tearc<T> {
    pub fn new(t: T) -> Self {
        let storage = Arc::pin(t);
        let pointer = &raw const *storage;
        Self { storage, pointer }
    }

    pub fn map<U: 'static>(this: Self, f: impl FnOnce(&T) -> &U) -> Tearc<U> {
        let storage = this.storage;
        let pointer = f(unsafe { &*this.pointer });
        Tearc { storage, pointer }
    }

    pub fn try_map<U: 'static>(this: Self, f: impl FnOnce(&T) -> Option<&U>) -> Option<Tearc<U>> {
        let storage = this.storage;
        let pointer = f(unsafe { &*this.pointer });
        pointer.map(|p| Tearc {
            storage,
            pointer: p,
        })
    }

    pub fn try_map_or_err<U: 'static, E>(
        this: Self,
        f: impl FnOnce(&T) -> Result<&U, E>,
    ) -> Result<Tearc<U>, E> {
        let storage = this.storage;
        let pointer = f(unsafe { &*this.pointer });
        pointer.map(|p| Tearc {
            storage,
            pointer: p,
        })
    }
}

impl<T: Unpin + 'static> From<Arc<T>> for Tearc<T> {
    fn from(t: Arc<T>) -> Self {
        let storage = Pin::new(t);
        let pointer = &raw const *storage;
        Self { storage, pointer }
    }
}

impl<T: 'static> Clone for Tearc<T> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            pointer: self.pointer.clone(),
        }
    }
}

impl<T: 'static> Deref for Tearc<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.pointer }
    }
}

impl<T: Default + 'static> Default for Tearc<T> {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

use std::{num::NonZeroUsize, sync::Arc};

use ahash::AHashMap;
use lru::LruCache;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use thiserror::Error;

use crate::tearc::Tearc;

#[derive(Debug, Error)]
pub enum INodeNotFoundError {
    #[error("inode not found")]
    INodeNotInTable,
    #[error("inode not initialized")]
    INodeNotInitialized,
}

pub struct MaybeExistingINode<T>(pub Option<Arc<OnceCell<T>>>);

impl<T> MaybeExistingINode<T> {
    pub fn unwrap(&self) -> anyhow::Result<&T> {
        Ok(self
            .0
            .as_ref()
            .ok_or(INodeNotFoundError::INodeNotInTable)?
            .get()
            .ok_or(INodeNotFoundError::INodeNotInitialized)?)
    }
}

pub struct MaybeInitializedINode<T>(pub Arc<OnceCell<T>>);

impl<T> MaybeInitializedINode<T> {
    pub fn get_or_create(&self, creator: impl FnOnce() -> anyhow::Result<T>) -> anyhow::Result<&T> {
        self.0.get_or_try_init(creator)
    }

    pub fn unwrap(&self) -> anyhow::Result<&T> {
        Ok(self
            .0
            .get()
            .ok_or(INodeNotFoundError::INodeNotInitialized)?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct INodeNumber(pub u64);
pub trait GenericINodeTable<T: 'static> {
    fn root_ino(&self) -> INodeNumber;
    fn get(&self, ino: INodeNumber) -> Option<Tearc<T>>;
    fn get_or_try_insert_with(
        &self,
        ino: INodeNumber,
        f: impl FnOnce() -> anyhow::Result<T>,
    ) -> anyhow::Result<Tearc<T>>;
    fn clean_up_if(&self, ino: INodeNumber, predicate: impl FnOnce(&T) -> bool);
}

pub struct ShardedMapINodeTable<T: 'static> {
    root_ino: INodeNumber,
    root_node: Tearc<T>,
    table: Vec<Mutex<AHashMap<INodeNumber, Tearc<OnceCell<T>>>>>,
    distributor: ahash::RandomState,
}

impl<T: 'static> ShardedMapINodeTable<T> {
    pub fn new(root_ino: INodeNumber, root_node: T, shard_count: usize) -> Self {
        Self {
            root_ino,
            root_node: Tearc::new(root_node),
            table: (0..shard_count)
                .map(|_| Mutex::new(AHashMap::new()))
                .collect(),
            distributor: ahash::RandomState::new(),
        }
    }

    fn get_index(&self, ino: INodeNumber) -> usize {
        self.distributor.hash_one(ino) as usize % self.table.len()
    }
}

impl<T: 'static> GenericINodeTable<T> for ShardedMapINodeTable<T> {
    fn root_ino(&self) -> INodeNumber {
        self.root_ino
    }

    fn clean_up_if(&self, ino: INodeNumber, predicate: impl FnOnce(&T) -> bool) {
        if ino == self.root_ino {
            return;
        }
        let mut table = self.table[self.get_index(ino)].lock();
        let node = table.get(&ino);
        if node.is_some_and(|v| v.get().is_some_and(predicate)) {
            table.remove(&ino);
        }
    }

    fn get(&self, ino: INodeNumber) -> Option<Tearc<T>> {
        if ino == self.root_ino {
            Some(self.root_node.clone())
        } else {
            let t = self.table[self.get_index(ino)].lock().get(&ino).cloned()?;
            Tearc::try_map(t, |o| o.get())
        }
    }

    fn get_or_try_insert_with(
        &self,
        ino: INodeNumber,
        f: impl FnOnce() -> anyhow::Result<T>,
    ) -> anyhow::Result<Tearc<T>> {
        if ino == self.root_ino {
            Ok(self.root_node.clone())
        } else {
            let row: Tearc<OnceCell<T>> = self.table[self.get_index(ino)]
                .lock()
                .entry(ino)
                .or_default()
                .clone();
            Tearc::try_map_or_err(row, |o| o.get_or_try_init(f))
        }
    }
}

pub struct ShardedLruINodeTable<T: 'static> {
    root_ino: INodeNumber,
    root_node: Tearc<T>,
    table: Vec<Mutex<LruCache<INodeNumber, Tearc<OnceCell<T>>, ahash::RandomState>>>,
    distributor: ahash::RandomState,
}

impl<T: 'static> ShardedLruINodeTable<T> {
    pub fn new(
        root_ino: INodeNumber,
        root_node: T,
        shard_count: usize,
        capacity_per_shard: NonZeroUsize,
    ) -> Self {
        Self {
            root_ino,
            root_node: Tearc::new(root_node),
            table: (0..shard_count)
                .map(|_| {
                    Mutex::new(LruCache::<
                        INodeNumber,
                        Tearc<OnceCell<T>>,
                        ahash::RandomState,
                    >::with_hasher(
                        capacity_per_shard, ahash::RandomState::new()
                    ))
                })
                .collect(),
            distributor: ahash::RandomState::new(),
        }
    }

    fn get_index(&self, ino: INodeNumber) -> usize {
        self.distributor.hash_one(ino) as usize % self.table.len()
    }
}

impl<T: 'static> GenericINodeTable<T> for ShardedLruINodeTable<T> {
    fn root_ino(&self) -> INodeNumber {
        self.root_ino
    }

    fn get(&self, ino: INodeNumber) -> Option<Tearc<T>> {
        if ino == self.root_ino {
            Some(self.root_node.clone())
        } else {
            let t = self.table[self.get_index(ino)].lock().get(&ino).cloned()?;
            Tearc::try_map(t, |o| o.get())
        }
    }

    fn get_or_try_insert_with(
        &self,
        ino: INodeNumber,
        f: impl FnOnce() -> anyhow::Result<T>,
    ) -> anyhow::Result<Tearc<T>> {
        if ino == self.root_ino {
            Ok(self.root_node.clone())
        } else {
            let row: Tearc<OnceCell<T>> = self.table[self.get_index(ino)]
                .lock()
                .get_or_insert(ino, Default::default)
                .clone();
            Tearc::try_map_or_err(row, |o| o.get_or_try_init(f))
        }
    }

    fn clean_up_if(&self, ino: INodeNumber, predicate: impl FnOnce(&T) -> bool) {
        if ino == self.root_ino {
            return;
        }
        let mut table = self.table[self.get_index(ino)].lock();
        let node = table.get(&ino);
        if node.is_some_and(|v| v.get().is_some_and(predicate)) {
            table.demote(&ino);
        }
    }
}
#[cfg(unix)]
pub mod unix {

    use ambassador::delegatable_trait;
    use rustix::fs::Timespec;
    use std::sync::atomic::AtomicI64;

    use crate::tearc::Tearc;

    pub use super::INodeNumber;

    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
    pub struct Generation(pub u64);

    #[delegatable_trait]
    pub trait INodeCore<StatType> {
        fn get_ino(&self) -> INodeNumber;
        fn get_generation(&self) -> Generation;
        fn get_lookup_count(&self) -> &AtomicI64;
        fn get_metadata(&self) -> anyhow::Result<StatType>;
        fn set_metadata(
            &self,
            mode: Option<libc::mode_t>,
            uid: Option<libc::uid_t>,
            gid: Option<libc::gid_t>,
            size: Option<u64>,
            atime: Option<Timespec>,
            mtime: Option<Timespec>,
            ctime: Option<Timespec>,
            crtime: Option<Timespec>,
        ) -> anyhow::Result<()>;
        fn get_extended_attr(&self, name: &[u8]) -> anyhow::Result<Vec<u8>>;
        fn set_extended_attr(&self, name: &[u8], value: &[u8]) -> anyhow::Result<()>;
        fn remove_extended_attr(&self, name: &[u8]) -> anyhow::Result<()>;
        fn list_extended_attrs(&self) -> anyhow::Result<Vec<Vec<u8>>>;
    }

    #[derive(Copy, Clone)]
    pub enum FileType {
        DIRECTORY,
        FILE,
        SYMLINK,
    }

    pub struct DirEntry<'a> {
        pub ino: INodeNumber,
        pub filetype: FileType,
        pub offset: i64,
        pub name: &'a [u8],
    }

    pub struct OwnedDirEntry {
        pub ino: INodeNumber,
        pub filetype: FileType,
        pub offset: i64,
        pub name: Vec<u8>,
    }

    impl OwnedDirEntry {
        pub fn to_ref(&self) -> DirEntry<'_> {
            DirEntry {
                ino: self.ino,
                filetype: self.filetype,
                offset: self.offset,
                name: self.name.as_slice(),
            }
        }
    }

    pub trait DirReader {
        fn iterate_from(
            &mut self,
            offset: i64,
            f: impl FnMut(&DirEntry) -> anyhow::Result<bool>,
        ) -> anyhow::Result<()>;
    }

    pub trait DirINodeExt: Sized {
        type DirReader: DirReader;
        fn create_dir_reader(this: Tearc<Self>) -> anyhow::Result<Self::DirReader>;
    }

    pub trait FileINodeExt {
        fn read(&self, data: &mut [u8], offset: u64) -> anyhow::Result<usize>;
        fn write(&self, data: &[u8], offset: u64) -> anyhow::Result<()>;
        fn append(&self, data: &[u8]) -> anyhow::Result<()>;
        fn size(&self) -> anyhow::Result<u64>;
    }

    pub trait SymlinkINodeExt {
        fn readlink(&self) -> anyhow::Result<Vec<u8>>;
    }
}

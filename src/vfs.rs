use std::{hash::BuildHasher, num::NonZeroUsize, sync::Arc};

use ahash::AHashMap;
use lru::LruCache;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use thiserror::Error;

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
pub trait GenericINodeTable<T> {
    fn root_ino(&self) -> INodeNumber;
    fn get(&self, ino: INodeNumber) -> MaybeExistingINode<T>;
    fn get_or_insert_default(&self, ino: INodeNumber) -> MaybeInitializedINode<T>;
    fn clean_up_if(&self, ino: INodeNumber, predicate: impl FnOnce(&T) -> bool);
}

pub struct ShardedMapINodeTable<T> {
    root_ino: INodeNumber,
    root_node: Arc<OnceCell<T>>,
    table: Vec<Mutex<AHashMap<INodeNumber, Arc<OnceCell<T>>>>>,
    distributor: ahash::RandomState,
}

impl<T> ShardedMapINodeTable<T> {
    pub fn new(root_ino: INodeNumber, root_node: T, shard_count: usize) -> Self {
        Self {
            root_ino,
            root_node: Arc::new(OnceCell::with_value(root_node)),
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

impl<T> GenericINodeTable<T> for ShardedMapINodeTable<T> {
    fn root_ino(&self) -> INodeNumber {
        self.root_ino
    }

    fn get(&self, ino: INodeNumber) -> MaybeExistingINode<T> {
        if ino == self.root_ino {
            MaybeExistingINode(Some(self.root_node.clone()))
        } else {
            MaybeExistingINode(self.table[self.get_index(ino)].lock().get(&ino).cloned())
        }
    }

    fn get_or_insert_default(&self, ino: INodeNumber) -> MaybeInitializedINode<T> {
        if ino == self.root_ino {
            MaybeInitializedINode(self.root_node.clone())
        } else {
            MaybeInitializedINode(
                self.table[self.get_index(ino)]
                    .lock()
                    .entry(ino)
                    .or_default()
                    .clone(),
            )
        }
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
}

pub struct ShardedLruINodeTable<T> {
    root_ino: INodeNumber,
    root_node: Arc<OnceCell<T>>,
    table: Vec<Mutex<LruCache<INodeNumber, Arc<OnceCell<T>>, ahash::RandomState>>>,
    distributor: ahash::RandomState,
}

impl<T> ShardedLruINodeTable<T> {
    pub fn new(
        root_ino: INodeNumber,
        root_node: T,
        shard_count: usize,
        capacity_per_shard: NonZeroUsize,
    ) -> Self {
        Self {
            root_ino,
            root_node: Arc::new(OnceCell::with_value(root_node)),
            table: (0..shard_count)
                .map(|_| {
                    Mutex::new(
                        LruCache::<INodeNumber, Arc<OnceCell<T>>, ahash::RandomState>::with_hasher(
                            capacity_per_shard,
                            ahash::RandomState::new(),
                        ),
                    )
                })
                .collect(),
            distributor: ahash::RandomState::new(),
        }
    }

    fn get_index(&self, ino: INodeNumber) -> usize {
        self.distributor.hash_one(ino) as usize % self.table.len()
    }
}

impl<T> GenericINodeTable<T> for ShardedLruINodeTable<T> {
    fn root_ino(&self) -> INodeNumber {
        self.root_ino
    }

    fn get(&self, ino: INodeNumber) -> MaybeExistingINode<T> {
        if ino == self.root_ino {
            MaybeExistingINode(Some(self.root_node.clone()))
        } else {
            MaybeExistingINode(self.table[self.get_index(ino)].lock().get(&ino).cloned())
        }
    }

    fn get_or_insert_default(&self, ino: INodeNumber) -> MaybeInitializedINode<T> {
        if ino == self.root_ino {
            MaybeInitializedINode(self.root_node.clone())
        } else {
            MaybeInitializedINode(
                self.table[self.get_index(ino)]
                    .lock()
                    .get_or_insert(ino, Default::default)
                    .clone(),
            )
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

    use rustix::fs::Timespec;
    use std::sync::atomic::AtomicI64;

    pub use super::INodeNumber;

    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
    pub struct Generation(pub u64);

    /// File attributes
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct INodeMetadata {
        /// Inode number
        pub ino: INodeNumber,
        /// Size in bytes
        pub size: u64,
        /// Size in blocks
        pub blocks: u64,
        /// Time of last access
        pub atime: Timespec,
        /// Time of last modification
        pub mtime: Timespec,
        /// Time of last change
        pub ctime: Timespec,
        /// Time of creation (macOS and FreeBSD)
        pub crtime: Timespec,
        /// Mode bits
        pub mode: u32,
        /// Number of hard links
        pub nlink: u32,
        /// User id
        pub uid: u32,
        /// Group id
        pub gid: u32,
        /// Rdev
        pub rdev: u32,
        /// Block size
        pub blksize: u32,
    }
    pub trait INodeCore<StatType> {
        fn get_ino(&self) -> INodeNumber;
        fn get_generation(&self) -> Generation;
        fn get_lookup_count(&self) -> &AtomicI64;
        fn get_metadata(&self) -> anyhow::Result<StatType>;
        fn set_metadata(
            &self,
            mode: Option<u32>,
            uid: Option<u32>,
            gid: Option<u32>,
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

    pub enum FileType {
        DIRECTORY,
        FILE,
        SYMLINK,
    }

    pub struct DirEntry {
        pub ino: INodeNumber,
        pub filetype: FileType,
        pub name: Vec<u8>,
        pub offset: i64,
    }

    pub trait DirReader {
        fn rewind(&mut self) -> anyhow::Result<()>;
        fn current_position(&self) -> i64;
        fn current(&self) -> Option<&DirEntry>;
        fn move_next(&mut self) -> anyhow::Result<bool>;
    }

    pub trait DirINodeExt {
        type DirReader: DirReader;
        fn create_dir_reader(&self) -> anyhow::Result<Self::DirReader>;
    }

    pub trait FileINodeExt {
        fn read(&self, data: &mut [u8], offset: u64) -> anyhow::Result<usize>;
        fn write(&self, data: &[u8], offset: u64) -> anyhow::Result<()>;
        fn append(&self, data: &[u8]) -> anyhow::Result<()>;
        fn size(&self) -> anyhow::Result<u64>;
        fn upgrade_to_writable(&self) -> anyhow::Result<()>;
    }

    pub trait SymlinkINodeExt {
        fn readlink(&self) -> anyhow::Result<Vec<u8>>;
    }
}

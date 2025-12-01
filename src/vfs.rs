use std::sync::Arc;

use parking_lot::Mutex;
#[cfg(unix)]
use rustix::fs::Timespec;

pub trait GenericHandle {
    fn get_lookup_count(&self) -> u64;
    fn increment_lookup_count(&self) -> u64;
    fn decrement_lookup_count(&self) -> u64;

    fn is_dir(&self) -> bool;
    fn is_regular_file(&self) -> bool;
    fn is_symlink(&self) -> bool;
}

pub trait GenericTable<H: GenericHandle> {
    fn lookup(&self, number: u64) -> Option<Arc<H>>;
    fn lookup_or_init(&self, number: u64) -> Arc<H>;
    fn notify_no_more_reference(&self, number: u64);
    fn cleanup(&self);
}

pub struct INodeTable<INode: GenericHandle + Default> {
    root_ino: u64,
    root: Arc<INode>,
    seed: u64,
    shards: Vec<Mutex<lru::LruCache<u64, Arc<INode>>>>,
}

impl<INode: GenericHandle + Default> INodeTable<INode> {
    pub fn new(root_ino: u64, seed: u64, num_shards: usize, root: Arc<INode>) -> Self {
        let mut v = Self {
            root_ino,
            seed,
            shards: Vec::with_capacity(num_shards),
            root,
        };
        for _ in 0..num_shards {
            v.shards.push(lru::LruCache::unbounded().into());
        }
        v
    }

    fn get_shard(&self, number: u64) -> &Mutex<lru::LruCache<u64, Arc<INode>>> {
        &self.shards[((number ^ self.seed) % self.shards.len() as u64) as usize]
    }
}

impl<INode: GenericHandle + Default> GenericTable<INode> for INodeTable<INode> {
    fn lookup(&self, number: u64) -> Option<Arc<INode>> {
        if number == self.root_ino {
            self.root.clone().into()
        } else {
            self.get_shard(number).lock().get(&number).cloned()
        }
    }

    fn lookup_or_init(&self, number: u64) -> Arc<INode> {
        if number == self.root_ino {
            self.root.clone()
        } else {
            self.get_shard(number)
                .lock()
                .get_or_insert(number, Default::default)
                .clone()
        }
    }

    fn notify_no_more_reference(&self, number: u64) {
        if number == self.root_ino {
            return;
        }
        self.get_shard(number).lock().demote(&number);
    }

    fn cleanup(&self) {
        for shard in &self.shards {
            if let Some(mut shard) = shard.try_lock() {
                for _ in 0..100 {
                    if let Some((k, v)) = shard.peek_lru().map(|(k, v)| (*k, v.clone())) {
                        if v.get_lookup_count() == 0 {
                            shard.pop_lru();
                            break;
                        } else {
                            shard.promote(&k);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
pub mod unix {

    use std::ffi::CString;

    use rustix::fs::Timespec;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct INodeNumber(pub u64);
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
        /// Permissions
        pub perm: u16,
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

    pub trait INodeCore {
        fn get_ino(&self) -> INodeNumber;
        fn get_generation(&self) -> Generation;
        fn get_metadata(&self) -> anyhow::Result<INodeMetadata>;
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
        fn seek(&mut self, offset: i64) -> anyhow::Result<()>;
        fn next(&mut self) -> anyhow::Result<Option<DirEntry>>;
    }

    pub trait DirINode: INodeCore {
        fn create_dir_reader(&self) -> anyhow::Result<Box<dyn DirReader>>;
    }

    pub trait FileINode: INodeCore {
        fn read(&self, data: &mut [u8], offset: u64) -> anyhow::Result<usize>;
        fn write(&self, data: &[u8], offset: u64) -> anyhow::Result<()>;
        fn size(&self) -> anyhow::Result<u64>;
        fn upgrade_to_writable(&self) -> anyhow::Result<()>;
    }

    pub trait SymlinkINode: INodeCore {
        fn readlink(&self) -> anyhow::Result<Vec<u8>>;
    }
}

#![cfg(unix)]

use std::ffi::{CStr, CString};
use std::os::fd::AsRawFd;

use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::time::Duration;
use std::{
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    sync::{Arc, atomic::AtomicI64},
};

use ambassador::{Delegate, delegatable_trait};
use anyhow::{Context, bail};
use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};
use rustix::fs::{AtFlags, Mode, OFlags, Timespec};

use crate::lite::LiteAesGcmCryptStreamFactory;
use crate::lite::long_name_db::{C_LONG_NAME_DB_FILENAME, LongNameLookupTable};
use crate::lite::name_translators::create_name_translator;
use crate::protos::params::decrypted_securefs_params::Format_specific_params;
use crate::protos::params::{DecryptedSecurefsParams, MountOptions};
use crate::tearc::Tearc;
use crate::vfs::{GenericINodeTable, ShardedMapINodeTable};
use crate::{
    lite::{
        IoWrapperFactory, IoWrapperStream,
        name_translators::{NameDecodeOutput, NameTranslator},
    },
    vfs::unix::{
        DirEntry, DirINodeExt, DirReader, FileINodeExt, Generation, INodeCore, INodeNumber,
        SymlinkINodeExt,
    },
};

fn new_timespec(sec: i64, nsec: i64) -> Timespec {
    Timespec {
        tv_sec: sec,
        tv_nsec: nsec,
    }
}

// Safe wrapper around libc::stat.
// We are not calling rustix here to avoid format conversion between rustix stat
// and libc stat,  and the latter is expected by libfuse.
pub(super) fn fstat(fd: BorrowedFd<'_>) -> anyhow::Result<libc::stat> {
    let mut result: libc::stat = unsafe { std::mem::zeroed() };
    if (unsafe { libc::fstat(fd.as_raw_fd(), &mut result) }) != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("Calling fstat on fd {}", fd.as_raw_fd()));
    }
    Ok(result)
}

// Safe wrapper around libc::stat.
// We are not calling rustix here to avoid format conversion between rustix stat
// and libc stat,  and the latter is expected by libfuse.
pub(super) fn fstatat(fd: BorrowedFd<'_>, path: &CStr) -> anyhow::Result<libc::stat> {
    let mut result: libc::stat = unsafe { std::mem::zeroed() };
    if (unsafe {
        libc::fstatat(
            fd.as_raw_fd(),
            path.as_ptr(),
            &mut result,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    }) != 0
    {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("Calling fstatat on fd={} path={:?}", fd.as_raw_fd(), path));
    }
    Ok(result)
}

pub struct LiteINodeHeader {
    pub ino: INodeNumber,
    pub generation: Generation,
    pub lookup_count: AtomicI64,
    pub name_translator: Arc<dyn NameTranslator>,
}

struct LiteFileNodeInner {
    stream: Box<dyn IoWrapperStream>,
    writable: bool,
}
pub struct LiteFileINode {
    header: LiteINodeHeader,
    inner: Mutex<LiteFileNodeInner>,
}

impl LiteFileINode {
    pub fn new(header: LiteINodeHeader, s: Box<dyn IoWrapperStream>, writable: bool) -> Self {
        Self {
            header,
            inner: Mutex::new(LiteFileNodeInner {
                stream: s,
                writable,
            }),
        }
    }

    pub fn open(
        header: LiteINodeHeader,
        parent: BorrowedFd<'_>,
        encoded_name: &[u8],
        writable: bool,
        wrapper_factory: &dyn IoWrapperFactory,
    ) -> anyhow::Result<Self> {
        let fd = rustix::fs::openat(
            parent,
            encoded_name,
            if writable {
                rustix::fs::OFlags::RDWR
            } else {
                rustix::fs::OFlags::RDONLY
            },
            rustix::fs::Mode::empty(),
        )?;

        Ok(Self {
            header,
            inner: Mutex::new(LiteFileNodeInner {
                stream: wrapper_factory.wrap(fd)?,
                writable,
            }),
        })
    }

    fn upgrade_to_writable(inner: &mut LiteFileNodeInner) -> anyhow::Result<()> {
        if inner.writable {
            return Ok(());
        }
        inner.stream.upgrade_to_writable()?;
        inner.writable = true;
        Ok(())
    }
}

impl ReadjustStatExt for LiteFileINode {
    fn readjust_stat(&self, st: &mut rustix::fs::Stat) -> anyhow::Result<()> {
        let inner = self.inner.lock();
        st.st_size = inner.stream.size()?.try_into()?;
        st.st_blksize = inner.stream.optimal_block_size().try_into()?;
        Ok(())
    }
}

impl INodeCore<rustix::fs::Stat> for LiteFileINode {
    fn get_ino(&self) -> INodeNumber {
        self.header.ino
    }

    fn get_generation(&self) -> Generation {
        self.header.generation
    }

    fn get_lookup_count(&self) -> &AtomicI64 {
        &self.header.lookup_count
    }

    fn get_metadata(&self) -> anyhow::Result<rustix::fs::Stat> {
        let inner = self.inner.lock();
        let mut stat = rustix::fs::fstat(inner.stream.as_fd())?;
        stat.st_size = inner.stream.size()?.try_into()?;
        stat.st_blksize = inner.stream.optimal_block_size().try_into()?;
        Ok(stat)
    }

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
    ) -> anyhow::Result<()> {
        todo!()
    }

    fn get_extended_attr(&self, name: &[u8]) -> anyhow::Result<Vec<u8>> {
        todo!()
    }

    fn set_extended_attr(&self, name: &[u8], value: &[u8]) -> anyhow::Result<()> {
        todo!()
    }

    fn remove_extended_attr(&self, name: &[u8]) -> anyhow::Result<()> {
        todo!()
    }

    fn list_extended_attrs(&self) -> anyhow::Result<Vec<Vec<u8>>> {
        todo!()
    }
}

impl FileINodeExt for LiteFileINode {
    fn read(&self, data: &mut [u8], offset: u64) -> anyhow::Result<usize> {
        Ok(self.inner.lock().stream.read(data, offset)?.try_into()?)
    }

    fn write(&self, data: &[u8], offset: u64) -> anyhow::Result<()> {
        let mut guard = self.inner.lock();
        LiteFileINode::upgrade_to_writable(&mut *guard)?;
        guard.stream.write(data, offset)
    }

    fn size(&self) -> anyhow::Result<u64> {
        self.inner.lock().stream.size()
    }

    fn append(&self, data: &[u8]) -> anyhow::Result<()> {
        let mut guard = self.inner.lock();
        LiteFileINode::upgrade_to_writable(&mut *guard)?;
        let size = guard.stream.size()?;
        guard.stream.write(data, size)?;
        Ok(())
    }
}

struct LiteDirNodeLongNameDb {
    // Note, since we first open the db as a file descriptor, we need to keep it alive as long as
    // the sqlite3 handle is open. If we close the file descriptor prematurely, it will destroy the
    // file locking internally in the sqlite3 handle.
    table_fd: OwnedFd,
    lookup_table: LongNameLookupTable,
    readonly: bool,
}
pub struct LiteDirINode {
    header: LiteINodeHeader,
    fd: OwnedFd,
    db: Mutex<Option<LiteDirNodeLongNameDb>>,
}

impl LiteDirINode {
    pub fn new(header: LiteINodeHeader, fd: OwnedFd) -> Self {
        Self {
            header,
            fd,
            db: Default::default(),
        }
    }

    pub fn open(
        header: LiteINodeHeader,
        parent: BorrowedFd<'_>,
        encoded_name: &[u8],
    ) -> anyhow::Result<Self> {
        let fd = rustix::fs::openat(
            parent,
            encoded_name,
            rustix::fs::OFlags::RDONLY,
            rustix::fs::Mode::empty(),
        )?;

        Ok(Self {
            header,
            fd,
            db: Default::default(),
        })
    }

    fn init_long_name_db(
        &self,
        db: &mut Option<LiteDirNodeLongNameDb>,
        readonly: bool,
    ) -> anyhow::Result<()> {
        let (flags, mode) = if readonly {
            (OFlags::RDONLY, Mode::empty())
        } else {
            (OFlags::RDWR | OFlags::CREATE, Mode::from_raw_mode(0o600))
        };
        let table_fd = rustix::fs::openat(self.fd.as_fd(), C_LONG_NAME_DB_FILENAME, flags, mode)?;
        let lookup_table = LongNameLookupTable::new(
            format!("/dev/fd/{}", table_fd.as_raw_fd()).as_str(),
            readonly,
        )?;
        *db = Some(LiteDirNodeLongNameDb {
            table_fd,
            lookup_table,
            readonly,
        });
        Ok(())
    }

    pub(super) fn ensure_readable_long_name_db(
        &self,
    ) -> anyhow::Result<MappedMutexGuard<'_, LongNameLookupTable>> {
        let guard = self.db.lock();
        let map_result = MutexGuard::try_map_or_err(guard, |db| {
            if db.is_none() {
                self.init_long_name_db(db, true)?;
            }
            anyhow::Ok(&mut db.as_mut().unwrap().lookup_table)
        });
        match map_result {
            Ok(result) => anyhow::Ok(result),
            Err(err) => Err(err.1)?,
        }
    }

    pub(super) fn ensure_writable_long_name_db(
        &self,
    ) -> anyhow::Result<MappedMutexGuard<'_, LongNameLookupTable>> {
        let guard = self.db.lock();
        let map_result = MutexGuard::try_map_or_err(guard, |db| {
            if let Some(inner) = db
                && inner.readonly
            {
                *db = None;
            }
            if db.is_none() {
                self.init_long_name_db(db, false)?;
            }
            anyhow::Ok(&mut db.as_mut().unwrap().lookup_table)
        });
        match map_result {
            Ok(result) => anyhow::Ok(result),
            Err(err) => Err(err.1)?,
        }
    }
}

impl AsFd for LiteDirINode {
    fn as_fd(&self) -> std::os::unix::prelude::BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl ReadjustStatExt for LiteDirINode {
    fn readjust_stat(&self, st: &mut rustix::fs::Stat) -> anyhow::Result<()> {
        Ok(())
    }
}

impl INodeCore<rustix::fs::Stat> for LiteDirINode {
    fn get_ino(&self) -> INodeNumber {
        self.header.ino
    }

    fn get_generation(&self) -> Generation {
        self.header.generation
    }

    fn get_lookup_count(&self) -> &AtomicI64 {
        &self.header.lookup_count
    }

    fn get_metadata(&self) -> anyhow::Result<rustix::fs::Stat> {
        Ok(rustix::fs::fstat(self.as_fd())?)
    }

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
    ) -> anyhow::Result<()> {
        todo!()
    }

    fn get_extended_attr(&self, name: &[u8]) -> anyhow::Result<Vec<u8>> {
        todo!()
    }

    fn set_extended_attr(&self, name: &[u8], value: &[u8]) -> anyhow::Result<()> {
        todo!()
    }

    fn remove_extended_attr(&self, name: &[u8]) -> anyhow::Result<()> {
        todo!()
    }

    fn list_extended_attrs(&self) -> anyhow::Result<Vec<Vec<u8>>> {
        todo!()
    }
}

impl DirINodeExt for LiteDirINode {
    type DirReader = LiteDirReader;
    fn create_dir_reader(this: Tearc<Self>) -> anyhow::Result<Self::DirReader> {
        Ok(LiteDirReader {
            dir: rustix::fs::Dir::read_from(this.fd.as_fd())?,
            inode: this,
            last_entry: None,
        })
    }
}

pub struct LiteDirReader {
    dir: rustix::fs::Dir,
    inode: Tearc<LiteDirINode>,
    last_entry: Option<OwnedDirEntry>,
}

impl DirReader for LiteDirReader {
    fn iterate_from(
        &mut self,
        offset: i64,
        mut f: impl FnMut(&DirEntry) -> anyhow::Result<bool>,
    ) -> anyhow::Result<()> {
        if self.last_entry.is_some() && offset == 0 {
            self.dir.rewind();
            self.last_entry = None;
        }
        if offset != 0
            && (self.last_entry.is_none()
                || self.last_entry.as_ref().is_some_and(|e| e.offset != offset))
        {
            bail!("only support pagination, not arbitary seek into directory")
        }
        loop {
            match self.dir.read() {
                None => {
                    return Ok(());
                }
                Some(Ok(entry)) => {
                    let filetype = match entry.file_type() {
                        rustix::fs::FileType::Directory => crate::vfs::unix::FileType::DIRECTORY,
                        rustix::fs::FileType::RegularFile => crate::vfs::unix::FileType::FILE,
                        rustix::fs::FileType::Symlink => crate::vfs::unix::FileType::SYMLINK,
                        _ => continue,
                    };
                    let name = if entry.file_name() == c"." || entry.file_name() == c".." {
                        NameDecodeOutput::Decoded(entry.file_name().to_bytes().to_vec())
                    } else if entry.file_name().to_bytes().starts_with(b".") {
                        continue;
                    } else {
                        self.inode
                            .header
                            .name_translator
                            .decode_name(entry.file_name().to_bytes())
                    };
                    match name {
                        NameDecodeOutput::Decoded(n) => {
                            self.last_entry = Some(OwnedDirEntry {
                                ino: INodeNumber(entry.ino()),
                                filetype,
                                name: n,
                                offset: match &self.last_entry {
                                    Some(e) => e.offset + 1,
                                    None => 1,
                                },
                            });
                        }
                        NameDecodeOutput::InvalidName => continue,
                        NameDecodeOutput::LongName => {
                            let fully_decrypted_name = self
                                .inode
                                .ensure_writable_long_name_db()?
                                .lookup(entry.file_name().to_bytes())?;
                            let Some(fully_encrypted_name) = fully_decrypted_name else {
                                tracing::warn!(
                                    "Encountered long name {:?} not recorded in the lookup table",
                                    entry.file_name()
                                );
                                continue;
                            };

                            let Some(n) = self
                                .inode
                                .header
                                .name_translator
                                .decrypt_name(&fully_encrypted_name)
                            else {
                                tracing::warn!(
                                    "Lookup table has recorded a name that cannot be correctly decrypted: {:?}",
                                    str::from_utf8(fully_encrypted_name.as_slice())
                                );
                                continue;
                            };
                            self.last_entry = Some(OwnedDirEntry {
                                ino: INodeNumber(entry.ino()),
                                filetype,
                                name: n,
                                offset: match &self.last_entry {
                                    Some(e) => e.offset + 1,
                                    None => 1,
                                },
                            });
                        }
                    }
                    if !f(&self.last_entry.as_ref().unwrap().to_ref())? {
                        return Ok(());
                    }
                }
                Some(Err(err)) => {
                    self.last_entry = None;
                    return Err(err)?;
                }
            }
        }
    }
}

pub struct LiteSymlinkINode {
    header: LiteINodeHeader,
    fd: OwnedFd,
    path: Option<CString>,
}

impl LiteSymlinkINode {
    fn new(header: LiteINodeHeader, fd: OwnedFd, path: Option<CString>) -> Self {
        Self { header, fd, path }
    }

    pub fn open(
        header: LiteINodeHeader,
        parent: BorrowedFd<'_>,
        encoded_name: CString,
    ) -> anyhow::Result<Self> {
        let fd = rustix::fs::openat(
            parent,
            encoded_name,
            #[cfg(target_os = "macos")]
            OFlags::from_bits_retain(libc::O_SYMLINK as libc::c_uint),
            #[cfg(not(target_os = "macos"))]
            OFlags::PATH,
            rustix::fs::Mode::empty(),
        )?;
        Ok(Self {
            header,
            fd,
            path: Default::default(),
        })
    }
}

impl INodeCore<rustix::fs::Stat> for LiteSymlinkINode {
    fn get_ino(&self) -> INodeNumber {
        self.header.ino
    }

    fn get_generation(&self) -> Generation {
        self.header.generation
    }

    fn get_lookup_count(&self) -> &AtomicI64 {
        &self.header.lookup_count
    }

    fn get_metadata(&self) -> anyhow::Result<rustix::fs::Stat> {
        match &self.path {
            Some(path) => Ok(rustix::fs::statat(
                self.fd.as_fd(),
                path,
                AtFlags::SYMLINK_NOFOLLOW,
            )?),
            None => Ok(rustix::fs::fstat(self.fd.as_fd())?),
        }
    }

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
    ) -> anyhow::Result<()> {
        todo!()
    }

    fn get_extended_attr(&self, name: &[u8]) -> anyhow::Result<Vec<u8>> {
        todo!()
    }

    fn set_extended_attr(&self, name: &[u8], value: &[u8]) -> anyhow::Result<()> {
        todo!()
    }

    fn remove_extended_attr(&self, name: &[u8]) -> anyhow::Result<()> {
        todo!()
    }

    fn list_extended_attrs(&self) -> anyhow::Result<Vec<Vec<u8>>> {
        todo!()
    }
}

impl SymlinkINodeExt for LiteSymlinkINode {
    fn readlink(&self) -> anyhow::Result<Vec<u8>> {
        todo!()
    }
}

impl ReadjustStatExt for LiteSymlinkINode {
    fn readjust_stat(&self, st: &mut rustix::fs::Stat) -> anyhow::Result<()> {
        st.st_size = self.readlink()?.len().try_into()?;
        Ok(())
    }
}

use crate::vfs::unix::{OwnedDirEntry, ambassador_impl_INodeCore};

#[delegatable_trait]
pub(super) trait ReadjustStatExt {
    fn readjust_stat(&self, st: &mut rustix::fs::Stat) -> anyhow::Result<()>;
}

#[derive(Delegate)]
#[delegate(INodeCore<rustix::fs::Stat>)]
#[delegate(ReadjustStatExt)]
pub enum LiteINode {
    LiteDirINode(LiteDirINode),
    LiteFileINode(LiteFileINode),
    LiteSymlinkINode(LiteSymlinkINode),
}

impl From<LiteDirINode> for LiteINode {
    fn from(value: LiteDirINode) -> Self {
        Self::LiteDirINode(value)
    }
}

impl From<LiteFileINode> for LiteINode {
    fn from(value: LiteFileINode) -> Self {
        Self::LiteFileINode(value)
    }
}

impl From<LiteSymlinkINode> for LiteINode {
    fn from(value: LiteSymlinkINode) -> Self {
        Self::LiteSymlinkINode(value)
    }
}

pub struct LiteVfs<Table: GenericINodeTable<LiteINode>> {
    pub(super) inode_table: Table,
    pub(super) name_translator: Arc<dyn NameTranslator>,
    pub(super) wrapper_factory: Box<dyn IoWrapperFactory>,
    pub(super) generation: AtomicU64,
    pub(super) device_serial: libc::dev_t,
    pub(super) attr_cache_duration: Duration,
    pub(super) readonly: bool,
}

fn create_vfs<Table: GenericINodeTable<LiteINode>, F: FnOnce(INodeNumber, LiteINode) -> Table>(
    data_params: &DecryptedSecurefsParams,
    mount_options: &MountOptions,
    data_dir: &Path,
    f: F,
) -> anyhow::Result<LiteVfs<Table>> {
    let Some(Format_specific_params::LiteFormatParams(ref lite_format_params)) =
        data_params.format_specific_params
    else {
        anyhow::bail!("Trying to create lite vfs without lite params");
    };

    let name_translator = create_name_translator(lite_format_params)?;
    let factory = Box::new(LiteAesGcmCryptStreamFactory::new_from_params(
        data_params,
        !mount_options.disable_verification,
    )?);

    let dir_fd = rustix::fs::open(data_dir, OFlags::RDONLY, Mode::empty())?;
    let st = rustix::fs::fstat(dir_fd.as_fd())?;
    let dir = LiteDirINode::new(
        LiteINodeHeader {
            ino: INodeNumber(st.st_ino),
            generation: Generation(0),
            lookup_count: AtomicI64::new(1),
            name_translator: name_translator.clone(),
        },
        dir_fd,
    );
    let inode_table = f(dir.header.ino, dir.into());
    Ok(LiteVfs::<Table> {
        inode_table,
        name_translator,
        wrapper_factory: factory,
        generation: AtomicU64::new(128),
        device_serial: st.st_dev,
        attr_cache_duration: Duration::from_secs(mount_options.attr_cache_seconds.unwrap_or(30)),
        readonly: mount_options.read_only,
    })
}

pub fn create_vfs_for_fuse(
    data_params: &DecryptedSecurefsParams,
    mount_options: &MountOptions,
    data_dir: &Path,
) -> anyhow::Result<LiteVfs<ShardedMapINodeTable<LiteINode>>> {
    let Some(crate::protos::params::mount_options::Mount_type_specific::MountByKernelExt(..)) =
        mount_options.mount_type_specific
    else {
        bail!("create_vfs_for_fuse called but the mount options are in the contrary")
    };
    create_vfs(data_params, mount_options, data_dir, |number, node| {
        let shard_count = if mount_options.inode_table_shard_count > 0 {
            mount_options
                .inode_table_shard_count
                .try_into()
                .expect("shard count too large")
        } else {
            256
        };
        ShardedMapINodeTable::new(number, node, shard_count)
    })
}

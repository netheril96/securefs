#![cfg(unix)]

use std::ffi::{CStr, CString};
use std::os::fd::AsRawFd;

use std::sync::atomic::AtomicU64;
use std::time::Duration;
use std::{
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    sync::{Arc, atomic::AtomicI64},
};

use anyhow::Context;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use rustix::fs::{AtFlags, OFlags, Timespec};

use crate::lite::name_translators::{NewStyleNameTranslator, create_name_translator};
use crate::protos::params::decrypted_securefs_params::{Format_specific_params, LiteFormatParams};
use crate::protos::params::{DecryptedSecurefsParams, MountOptions};
use crate::vfs::GenericINodeTable;
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
// We are not calling rustix here to avoid format conversion between rustix stat and libc stat,
//  and the latter is expected by libfuse.
pub(super) fn fstat(fd: BorrowedFd<'_>) -> anyhow::Result<libc::stat> {
    let mut result: libc::stat = unsafe { std::mem::zeroed() };
    if (unsafe { libc::fstat(fd.as_raw_fd(), &mut result) }) != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("Calling fstat on fd {}", fd.as_raw_fd()));
    }
    Ok(result)
}

// Safe wrapper around libc::stat.
// We are not calling rustix here to avoid format conversion between rustix stat and libc stat,
//  and the latter is expected by libfuse.
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

    fn readjust_stat(&self, st: &mut rustix::fs::Stat) -> anyhow::Result<()> {
        let inner = self.inner.lock();
        st.st_size = inner.stream.size()?.try_into()?;
        st.st_blksize = inner.stream.optimal_block_size().try_into()?;
        Ok(())
    }

    fn upgrade_to_writable(inner: &mut LiteFileNodeInner) -> anyhow::Result<()> {
        if inner.writable {
            return Ok(());
        }
        inner
            .stream
            .replace_fd(reopen_as_writable(inner.stream.as_fd())?);
        inner.writable = true;
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
    db_fd: OwnedFd,
    db: rusqlite::Connection,
}
pub struct LiteDirINode {
    header: LiteINodeHeader,
    fd: OwnedFd,
    db: OnceCell<LiteDirNodeLongNameDb>,
}

impl LiteDirINode {
    pub fn new(header: LiteINodeHeader, fd: OwnedFd) -> Self {
        Self {
            header,
            fd,
            db: OnceCell::new(),
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
            db: OnceCell::new(),
        })
    }

    fn readjust_stat(&self, st: &mut rustix::fs::Stat) -> anyhow::Result<()> {
        Ok(())
    }
}

impl AsFd for LiteDirINode {
    fn as_fd(&self) -> std::os::unix::prelude::BorrowedFd<'_> {
        self.fd.as_fd()
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
    fn create_dir_reader(&self) -> anyhow::Result<Self::DirReader> {
        Ok(LiteDirReader {
            dir: rustix::fs::Dir::read_from(self.fd.as_fd())?,
            name_translator: self.header.name_translator.clone(),
            current_offset: 0,
            current_entry: None,
        })
    }
}

pub struct LiteDirReader {
    dir: rustix::fs::Dir,
    name_translator: Arc<dyn NameTranslator>,
    current_offset: i64,
    current_entry: Option<DirEntry>,
}

impl DirReader for LiteDirReader {
    fn rewind(&mut self) -> anyhow::Result<()> {
        self.dir.rewind();
        Ok(())
    }

    fn current_position(&self) -> i64 {
        self.current_offset
    }

    fn current(&self) -> Option<&DirEntry> {
        self.current_entry.as_ref()
    }

    fn move_next(&mut self) -> anyhow::Result<bool> {
        loop {
            match self.dir.read() {
                None => {
                    self.current_entry = None;
                    return Ok(false);
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
                        self.name_translator
                            .decode_name(entry.file_name().to_bytes())
                    };
                    match name {
                        NameDecodeOutput::Decoded(n) => {
                            self.current_entry = Some(DirEntry {
                                ino: INodeNumber(entry.ino()),
                                filetype,
                                name: n,
                                offset: self.current_offset + 1,
                            });
                            self.current_offset += 1;
                            return Ok(true);
                        }
                        NameDecodeOutput::InvalidName => continue,
                        NameDecodeOutput::LongName => todo!(),
                    }
                }
                Some(Err(err)) => {
                    self.current_entry = None;
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

    fn readjust_stat(&self, st: &mut rustix::fs::Stat) -> anyhow::Result<()> {
        st.st_size = self.readlink()?.len().try_into()?;
        Ok(())
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

pub enum LiteINode {
    LiteDirINode(LiteDirINode),
    LiteFileINode(LiteFileINode),
    LiteSymlinkINode(LiteSymlinkINode),
}

impl LiteINode {
    pub(super) fn readjust_stat(&self, st: &mut rustix::fs::Stat) -> anyhow::Result<()> {
        match self {
            LiteINode::LiteDirINode(inode) => inode.readjust_stat(st),
            LiteINode::LiteFileINode(inode) => inode.readjust_stat(st),
            LiteINode::LiteSymlinkINode(inode) => inode.readjust_stat(st),
        }
    }
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

impl INodeCore<rustix::fs::Stat> for LiteINode {
    fn get_ino(&self) -> INodeNumber {
        match self {
            LiteINode::LiteDirINode(inode) => inode.get_ino(),
            LiteINode::LiteFileINode(inode) => inode.get_ino(),
            LiteINode::LiteSymlinkINode(inode) => inode.get_ino(),
        }
    }

    fn get_generation(&self) -> Generation {
        match self {
            LiteINode::LiteDirINode(inode) => inode.get_generation(),
            LiteINode::LiteFileINode(inode) => inode.get_generation(),
            LiteINode::LiteSymlinkINode(inode) => inode.get_generation(),
        }
    }

    fn get_lookup_count(&self) -> &AtomicI64 {
        match self {
            LiteINode::LiteDirINode(inode) => inode.get_lookup_count(),
            LiteINode::LiteFileINode(inode) => inode.get_lookup_count(),
            LiteINode::LiteSymlinkINode(inode) => inode.get_lookup_count(),
        }
    }

    fn get_metadata(&self) -> anyhow::Result<rustix::fs::Stat> {
        match self {
            LiteINode::LiteDirINode(inode) => inode.get_metadata(),
            LiteINode::LiteFileINode(inode) => inode.get_metadata(),
            LiteINode::LiteSymlinkINode(inode) => inode.get_metadata(),
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
        match self {
            LiteINode::LiteDirINode(inode) => {
                inode.set_metadata(mode, uid, gid, size, atime, mtime, ctime, crtime)
            }
            LiteINode::LiteFileINode(inode) => {
                inode.set_metadata(mode, uid, gid, size, atime, mtime, ctime, crtime)
            }
            LiteINode::LiteSymlinkINode(inode) => {
                inode.set_metadata(mode, uid, gid, size, atime, mtime, ctime, crtime)
            }
        }
    }

    fn get_extended_attr(&self, name: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            LiteINode::LiteDirINode(inode) => inode.get_extended_attr(name),
            LiteINode::LiteFileINode(inode) => inode.get_extended_attr(name),
            LiteINode::LiteSymlinkINode(inode) => inode.get_extended_attr(name),
        }
    }

    fn set_extended_attr(&self, name: &[u8], value: &[u8]) -> anyhow::Result<()> {
        match self {
            LiteINode::LiteDirINode(inode) => inode.set_extended_attr(name, value),
            LiteINode::LiteFileINode(inode) => inode.set_extended_attr(name, value),
            LiteINode::LiteSymlinkINode(inode) => inode.set_extended_attr(name, value),
        }
    }

    fn remove_extended_attr(&self, name: &[u8]) -> anyhow::Result<()> {
        match self {
            LiteINode::LiteDirINode(inode) => inode.remove_extended_attr(name),
            LiteINode::LiteFileINode(inode) => inode.remove_extended_attr(name),
            LiteINode::LiteSymlinkINode(inode) => inode.remove_extended_attr(name),
        }
    }

    fn list_extended_attrs(&self) -> anyhow::Result<Vec<Vec<u8>>> {
        match self {
            LiteINode::LiteDirINode(inode) => inode.list_extended_attrs(),
            LiteINode::LiteFileINode(inode) => inode.list_extended_attrs(),
            LiteINode::LiteSymlinkINode(inode) => inode.list_extended_attrs(),
        }
    }
}

#[cfg(target_os = "linux")]
fn reopen_as_writable(fd: BorrowedFd<'_>) -> anyhow::Result<OwnedFd> {
    use rustix::fs::Mode;
    Ok(rustix::fs::open(
        format!("/proc/self/fd/{}", fd.as_raw_fd()),
        OFlags::RDWR,
        Mode::empty(),
    )?)
}

#[cfg(target_os = "macos")]
fn reopen_as_writable(fd: BorrowedFd<'_>) -> anyhow::Result<OwnedFd> {
    use anyhow::Context;
    use rustix::fs::{Mode, OFlags};
    use std::ffi::CStr;

    let mut path_buffer = vec![0u8; (libc::PATH_MAX + 1) as usize];
    let ret = unsafe {
        libc::fcntl(
            fd.as_raw_fd(),
            libc::F_GETPATH,
            path_buffer.as_mut_ptr() as *mut libc::c_void,
        )
    };

    if ret < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("fcntl(F_GETPATH) failed for fd {}", fd.as_raw_fd()));
    }

    let path = unsafe { CStr::from_ptr(path_buffer.as_ptr() as *const libc::c_char) };
    Ok(rustix::fs::open(path, OFlags::RDWR, Mode::empty())?)
}

#[cfg(target_os = "freebsd")]
fn reopen_as_writable(fd: BorrowedFd<'_>) -> anyhow::Result<OwnedFd> {
    let opath_fd = rustix::fs::openat(
        fd,
        c"",
        OFlags::from_bits_retain((libc::O_PATH | libc::O_EMPTY_PATH) as libc::c_uint),
        rustix::fs::Mode::empty(),
    )?;
    Ok(rustix::fs::openat(
        opath_fd,
        c"",
        OFlags::from_bits_retain((libc::O_RDWR | libc::O_EMPTY_PATH) as libc::c_uint),
        rustix::fs::Mode::empty(),
    )?)
}

pub struct LiteVfs<Table: GenericINodeTable<LiteINode>> {
    pub(super) inode_table: Table,
    pub(super) name_translator: Arc<dyn NameTranslator>,
    pub(super) wrapper_factory: Box<dyn IoWrapperFactory>,
    pub(super) generation: AtomicU64,
    pub(super) device_serial: u64,
    pub(super) attr_cache_duration: Duration,
    pub(super) readonly: bool,
}

pub fn create_vfs<
    Table: GenericINodeTable<LiteINode>,
    F: FnOnce(INodeNumber, LiteINode) -> Table,
>(
    data_params: &DecryptedSecurefsParams,
    mount_options: &MountOptions,
    f: F,
) -> anyhow::Result<LiteVfs<Table>> {
    let Some(Format_specific_params::LiteFormatParams(ref lite_format_params)) =
        data_params.format_specific_params
    else {
        anyhow::bail!("Trying to create lite vfs without lite params");
    };

    let name_translator = create_name_translator(lite_format_params);

    todo!()
}

#[cfg(test)]
mod test {
    use std::{
        fs::File,
        io::{Read, Write},
    };

    use super::*;

    #[test]
    fn reopen() -> anyhow::Result<()> {
        let file = tempfile::NamedTempFile::new()?;
        file.as_file().write_all("Hello".as_bytes())?;

        let mut rofile = File::open(file.path())?;
        assert!(rofile.write_all("World".as_bytes()).is_err());

        let new_fd = reopen_as_writable(rofile.as_fd())?;
        let mut wfile = File::from(new_fd);

        let mut string = String::new();
        wfile.read_to_string(&mut string)?;
        assert_eq!(string, "Hello");

        wfile.write_all("World".as_bytes())?;
        Ok(())
    }
}

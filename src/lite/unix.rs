#![cfg(unix)]

use std::{
    ffi::{CString, OsString},
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    sync::{Arc, atomic::AtomicI64},
};

use enum_dispatch::enum_dispatch;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use rustix::fs::{OFlags, Stat, Timespec};

use crate::{
    lite::{
        IoWrapperFactory, IoWrapperStream,
        name_translators::{NameDecodeOutput, NameTranslator},
    },
    vfs::unix::{
        DirEntry, DirINodeExt, DirReader, FileINodeExt, Generation, INodeCore, INodeMetadata,
        INodeNumber, SymlinkINodeExt,
    },
};

fn new_timespec(sec: i64, nsec: i64) -> Timespec {
    Timespec {
        tv_sec: sec,
        tv_nsec: nsec,
    }
}

impl TryFrom<Stat> for INodeMetadata {
    type Error = anyhow::Error;

    fn try_from(st: Stat) -> Result<Self, Self::Error> {
        Ok(Self {
            ino: INodeNumber(st.st_ino.try_into()?),
            size: st.st_size.try_into()?,
            blocks: (st.st_size / 512).try_into()?,
            atime: new_timespec(st.st_atime, st.st_atime_nsec.try_into()?),
            mtime: new_timespec(st.st_mtime, st.st_mtime_nsec.try_into()?),
            ctime: new_timespec(st.st_ctime, st.st_ctime_nsec.try_into()?),
            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            crtime: new_timespec(st.st_birthtime, st.st_birthtime_nsec.try_into()?),
            #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
            crtime: new_timespec(st.st_ctime, st.st_ctime_nsec.try_into()?),
            nlink: st.st_nlink.try_into()?,
            uid: st.st_uid.try_into()?,
            gid: st.st_gid.try_into()?,
            rdev: st.st_rdev.try_into()?,
            blksize: st.st_blksize.try_into()?,
            mode: st.st_mode.try_into()?,
        })
    }
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
            header: header,
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
            header: header,
            inner: Mutex::new(LiteFileNodeInner {
                stream: wrapper_factory.wrap(fd)?,
                writable,
            }),
        })
    }
}

impl INodeCore for LiteFileINode {
    fn get_ino(&self) -> INodeNumber {
        self.header.ino
    }

    fn get_generation(&self) -> Generation {
        self.header.generation
    }

    fn get_lookup_count(&self) -> &AtomicI64 {
        &self.header.lookup_count
    }

    fn get_metadata(&self) -> anyhow::Result<INodeMetadata> {
        let inner = self.inner.lock();
        let mut stat = rustix::fs::fstat(inner.stream.as_fd())?;
        stat.st_size = inner.stream.size()?.try_into()?;
        let m: INodeMetadata = stat.try_into()?;
        Ok(m)
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

    fn maybe_size(&self) -> anyhow::Result<Option<u64>> {
        Ok(Some(self.size()?))
    }
}

impl FileINodeExt for LiteFileINode {
    fn read(&self, data: &mut [u8], offset: u64) -> anyhow::Result<usize> {
        Ok(self.inner.lock().stream.read(data, offset)?.try_into()?)
    }

    fn write(&self, data: &[u8], offset: u64) -> anyhow::Result<()> {
        self.inner.lock().stream.write(data, offset)
    }

    fn size(&self) -> anyhow::Result<u64> {
        self.inner.lock().stream.size()
    }

    fn upgrade_to_writable(&self) -> anyhow::Result<()> {
        todo!()
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
            header: header,
            fd: fd,
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
            header: header,
            fd: fd,
            db: OnceCell::new(),
        })
    }
}

impl AsFd for LiteDirINode {
    fn as_fd(&self) -> std::os::unix::prelude::BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl INodeCore for LiteDirINode {
    fn get_ino(&self) -> INodeNumber {
        self.header.ino
    }

    fn get_generation(&self) -> Generation {
        self.header.generation
    }

    fn get_lookup_count(&self) -> &AtomicI64 {
        &self.header.lookup_count
    }

    fn get_metadata(&self) -> anyhow::Result<INodeMetadata> {
        let stat = rustix::fs::fstat(self.fd.as_fd())?;
        let m: INodeMetadata = stat.try_into()?;
        Ok(m)
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

    fn maybe_size(&self) -> anyhow::Result<Option<u64>> {
        Ok(None)
    }
}

impl DirINodeExt for LiteDirINode {
    fn create_dir_reader(&self) -> anyhow::Result<Box<dyn DirReader>> {
        Ok(Box::new(LiteDirReader {
            dir: rustix::fs::Dir::read_from(self.fd.as_fd())?,
            name_translator: self.header.name_translator.clone(),
        }))
    }
}

struct LiteDirReader {
    dir: rustix::fs::Dir,
    name_translator: Arc<dyn NameTranslator>,
}

impl DirReader for LiteDirReader {
    fn rewind(&mut self) -> anyhow::Result<()> {
        self.dir.rewind();
        Ok(())
    }

    fn seek(&mut self, offset: i64) -> anyhow::Result<()> {
        self.dir.seek(offset)?;
        Ok(())
    }

    fn next(&mut self) -> anyhow::Result<Option<DirEntry>> {
        loop {
            match self.dir.read() {
                None => break Ok(None),
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
                            break Ok(Some(DirEntry {
                                ino: INodeNumber(entry.ino()),
                                filetype: filetype,
                                name: n,
                                offset: entry.offset(),
                            }));
                        }
                        NameDecodeOutput::InvalidName => continue,
                        NameDecodeOutput::LongName => todo!(),
                    }
                }
                Some(Err(err)) => break Err(err.into()),
            }
        }
    }
}

pub struct LiteSymlinkINode {
    header: LiteINodeHeader,
    fd: OwnedFd,
    path: Vec<u8>,
}

impl LiteSymlinkINode {
    fn new(header: LiteINodeHeader, fd: OwnedFd, path: Vec<u8>) -> Self {
        Self {
            header: header,
            fd: fd,
            path: path,
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
            OFlags::PATH,
            rustix::fs::Mode::empty(),
        )?;
        Ok(Self {
            header,
            fd: fd,
            path: Default::default(),
        })
    }
}

impl INodeCore for LiteSymlinkINode {
    fn get_ino(&self) -> INodeNumber {
        self.header.ino
    }

    fn get_generation(&self) -> Generation {
        self.header.generation
    }

    fn get_lookup_count(&self) -> &AtomicI64 {
        &self.header.lookup_count
    }

    fn get_metadata(&self) -> anyhow::Result<INodeMetadata> {
        todo!()
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

    fn maybe_size(&self) -> anyhow::Result<Option<u64>> {
        todo!()
    }
}

impl SymlinkINodeExt for LiteSymlinkINode {
    fn readlink(&self) -> anyhow::Result<Vec<u8>> {
        todo!()
    }
}

#[enum_dispatch(INodeCore)]
pub enum LiteINode {
    LiteDirINode,
    LiteFileINode,
    LiteSymlinkINode,
}

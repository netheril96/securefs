use std::{
    ffi::OsString,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    sync::{OnceLock, atomic::AtomicU64},
    time::Duration,
};

use parking_lot::Mutex;

use crate::{
    lite::name_translators::NameTranslator,
    stream::{LengthType, Stream},
    vfs::{GenericHandle, INodeTable},
};

pub const MAX_LOCK_DURATION: Duration = Duration::from_secs(5);

#[derive(Default)]
pub(super) enum InnerRepr {
    #[default]
    Uninit,
    Dir(LiteDir),
    RegularFile(LiteFile),
    Symlink(LiteSymlink),
}

pub(super) struct LiteDir {
    fd: OwnedFd,
}

impl LiteDir {
    pub(super) fn new(fd: OwnedFd) -> Self {
        Self { fd }
    }

    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub(super) fn stat(&mut self) -> anyhow::Result<rustix::fs::Stat> {
        Ok(rustix::fs::fstat(self.as_fd())?)
    }
}

pub(super) struct LiteFile {
    stream: Box<dyn IoWrapperStream>,
    writable: bool,
}

impl LiteFile {
    pub(super) fn new(stream: Box<dyn IoWrapperStream>, writable: bool) -> Self {
        Self { stream, writable }
    }

    pub(super) fn as_fd(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }

    pub(super) fn upgrade_to_writable_fd(&mut self, fd: OwnedFd, writable: bool) {
        if !writable {
            return;
        }
        self.stream.replace_fd(fd);
        self.writable = writable;
    }

    pub(super) fn is_writable(&self) -> bool {
        self.writable
    }

    pub(super) fn get_stream(&mut self) -> &mut dyn IoWrapperStream {
        self.stream.as_mut()
    }

    pub(super) fn stat(&mut self) -> anyhow::Result<rustix::fs::Stat> {
        let mut st = rustix::fs::fstat(self.as_fd())?;
        st.st_size = self.get_stream().size()?.try_into()?;
        Ok(st)
    }
}

pub(super) struct LiteSymlink {
    fd: OwnedFd,
    encoded_name: Vec<u8>,
}

impl LiteSymlink {
    pub(super) fn new(fd: OwnedFd, encoded_name: Vec<u8>) -> Self {
        Self { fd, encoded_name }
    }

    pub(super) fn stat(&self, nt: &dyn NameTranslator) -> anyhow::Result<rustix::fs::Stat> {
        let mut st = rustix::fs::statat(
            self.fd.as_fd(),
            &self.encoded_name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )?;
        st.st_size = self.readlink(nt)?.len().try_into()?;
        Ok(st)
    }

    pub(super) fn readlink(&self, nt: &dyn NameTranslator) -> anyhow::Result<Vec<u8>> {
        let raw = rustix::fs::readlinkat(self.fd.as_fd(), &self.encoded_name, vec![])?;
        nt.decode_path_for_symlink(raw.as_bytes())
    }
}

impl InnerRepr {
    pub fn ensure_dir<F>(&mut self, f: F) -> anyhow::Result<()>
    where
        F: FnOnce() -> anyhow::Result<LiteDir>,
    {
        match self {
            InnerRepr::Uninit => {
                *self = InnerRepr::Dir(f()?);
            }
            _ => {}
        }
        Ok(())
    }

    pub fn ensure_regular_file<F>(&mut self, f: F) -> anyhow::Result<()>
    where
        F: FnOnce() -> anyhow::Result<LiteFile>,
    {
        match self {
            InnerRepr::Uninit => {
                *self = InnerRepr::RegularFile(f()?);
            }
            _ => {}
        }
        Ok(())
    }

    pub fn ensure_symlink<F>(&mut self, f: F) -> anyhow::Result<()>
    where
        F: FnOnce() -> anyhow::Result<LiteSymlink>,
    {
        match self {
            InnerRepr::Uninit => {
                *self = InnerRepr::Symlink(f()?);
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct LiteINode {
    pub(super) lookup_count: AtomicU64,
    pub(super) generation: AtomicU64,
    pub(super) inner_repr: Mutex<InnerRepr>,
}

impl GenericHandle for LiteINode {
    fn get_lookup_count(&self) -> u64 {
        self.lookup_count.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn increment_lookup_count(&self) -> u64 {
        self.lookup_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1
    }

    fn decrement_lookup_count(&self) -> u64 {
        self.lookup_count
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst)
            - 1
    }

    fn is_dir(&self) -> bool {
        match *self.inner_repr.lock() {
            InnerRepr::Dir { .. } => true,
            _ => false,
        }
    }

    fn is_regular_file(&self) -> bool {
        match *self.inner_repr.lock() {
            InnerRepr::RegularFile { .. } => true,
            _ => false,
        }
    }

    fn is_symlink(&self) -> bool {
        false
    }
}

pub trait IoWrapperStream: Stream {
    fn as_fd(&self) -> BorrowedFd<'_>;
    fn replace_fd(&mut self, fd: OwnedFd);
}

pub trait IoWrapperOpener {
    fn compute_virtual_size(&self, underlying_size: LengthType) -> Option<LengthType>;
    fn wrap(&self, fd: OwnedFd) -> anyhow::Result<Box<dyn IoWrapperStream>>;
}

pub struct Vfs {
    pub(super) inode_table: INodeTable<LiteINode>,
    pub(super) name_translator: Box<dyn NameTranslator>,
    pub(super) wrapper_opener: Box<dyn IoWrapperOpener>,
    pub(super) generation: AtomicU64,
    pub(super) device_serial: OnceLock<u64>,
}

impl Vfs {}

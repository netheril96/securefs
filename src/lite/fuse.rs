#![cfg(feature = "fuse")]
#![cfg(not(windows))]

use std::{
    ffi::c_int,
    os::{
        fd::{AsRawFd, BorrowedFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    sync::{Arc, atomic::Ordering},
    time::{Duration, SystemTime},
};

use anyhow::anyhow;
use fuser::FileAttr;
use rustix::{fs::OFlags, io::Errno};

use crate::{
    lite::vfs::{
        InnerRepr, LiteDir, LiteFile, LiteINode, LiteOpenedData, LiteOpenedDescriptor, LiteSymlink,
        MAX_LOCK_DURATION, Vfs, reopen_as_writable,
    },
    vfs::{GenericHandle, GenericTable},
};

impl fuser::Filesystem for Vfs {
    fn lookup(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        log::trace!("lookup(_req={_req:?}, parent={parent:?}, name={name:?})");
        let inner = || -> anyhow::Result<(FileAttr, u64)> {
            let parent_node = self.inode_table.lookup(parent).ok_or(Errno::NOENT)?;
            let parent_node = parent_node
                .inner_repr
                .try_lock_for(MAX_LOCK_DURATION)
                .ok_or(Errno::DEADLOCK)?;
            let InnerRepr::Dir(parent_dir) = &*parent_node else {
                return Err(Errno::NOTDIR)?;
            };
            let enc_name = self.name_translator.encode_name(name.as_bytes())?;
            let mut stat = rustix::fs::statat(
                parent_dir.as_fd(),
                &enc_name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )?;
            if stat.st_dev != *self.device_serial.get_or_init(|| stat.st_dev) {
                log::error!(
                    "The underlying filesystem must be on the same device, or securefs cannot obtain stable inode IDs."
                );
                return Err(Errno::IO)?;
            }

            let file_type = rustix::fs::FileType::from_raw_mode(stat.st_mode);

            let child_node = self.inode_table.lookup_or_init(stat.st_ino);
            let _ = child_node.generation.compare_exchange(
                0,
                self.generation.load(Ordering::SeqCst),
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            child_node.increment_lookup_count();

            let mut child_repr = child_node
                .inner_repr
                .try_lock_for(MAX_LOCK_DURATION)
                .ok_or(Errno::DEADLOCK)?;

            if let InnerRepr::Uninit = &*child_repr {
                match file_type {
                    rustix::fs::FileType::Directory => {
                        child_repr.ensure_dir(|| {
                            let child_fd: OwnedFd = rustix::fs::openat(
                                parent_dir.as_fd(),
                                &enc_name,
                                rustix::fs::OFlags::RDONLY,
                                rustix::fs::Mode::empty(),
                            )?;
                            Ok(LiteDir::new(child_fd))
                        })?;
                    }
                    rustix::fs::FileType::RegularFile => {
                        let writable = if rustix::fs::Mode::from_raw_mode(stat.st_mode)
                            & rustix::fs::Mode::WUSR
                            != rustix::fs::Mode::empty()
                        {
                            true
                        } else {
                            false
                        };
                        child_repr.ensure_regular_file(|| {
                            let child_fd: OwnedFd = rustix::fs::openat(
                                parent_dir.as_fd(),
                                &enc_name,
                                if writable {
                                    rustix::fs::OFlags::RDWR
                                } else {
                                    rustix::fs::OFlags::RDONLY
                                },
                                rustix::fs::Mode::empty(),
                            )?;
                            Ok(LiteFile::new(self.wrapper_opener.wrap(child_fd)?, writable))
                        })?;
                    }
                    rustix::fs::FileType::Symlink => {
                        child_repr.ensure_symlink(|| {
                            Ok(LiteSymlink::new(
                                rustix::io::dup(parent_dir.as_fd())?,
                                enc_name,
                            ))
                        })?;
                    }
                    _ => Err(anyhow!("Unrecognized file type"))?,
                }
            }

            match &mut *child_repr {
                InnerRepr::RegularFile(lite_file) => {
                    stat.st_size = lite_file.get_stream().size()?.try_into()?;
                }
                InnerRepr::Symlink(lite_symlink) => {
                    stat.st_size = lite_symlink
                        .readlink(self.name_translator.as_ref())?
                        .len()
                        .try_into()?
                }
                _ => {}
            }

            Ok((
                stat_to_fileattr(&stat)?,
                child_node.generation.load(Ordering::SeqCst),
            ))
        };
        match inner() {
            Ok((attr, generation)) => {
                log::trace!(
                    "lookup(_req={_req:?}, parent={parent:?}, name={name:?}) = (attr={attr:?}, generation={generation})"
                );
                reply.entry(&Duration::from_secs(30), &attr, generation);
            }
            Err(err) => {
                log::trace!(
                    "lookup(_req={_req:?}, parent={parent:?}, name={name:?}) results in error {err:?}"
                );
                log::warn!("lookup(parent={parent:?}, name={name:?}) results in error {err:?}");
                reply.error(extract_errno(&err));
            }
        }
    }

    fn getattr(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: Option<u64>,
        reply: fuser::ReplyAttr,
    ) {
        log::trace!("getattr(_req={_req:?}, ino={ino:?}, fh={fh:?})");
        let inner = || -> anyhow::Result<FileAttr> {
            let node: Arc<LiteINode>;
            if let Some(fh) = fh {
                node = unsafe {
                    (fh as *mut LiteOpenedDescriptor)
                        .as_ref()
                        .unwrap()
                        .inode
                        .clone()
                };
            } else {
                node = self.inode_table.lookup(ino).ok_or(Errno::NOENT)?;
            }
            let mut node = node
                .inner_repr
                .try_lock_for(MAX_LOCK_DURATION)
                .ok_or(Errno::DEADLOCK)?;

            let st = match &mut *node {
                InnerRepr::Uninit => Err(Errno::INPROGRESS)?,
                InnerRepr::Dir(lite_dir) => lite_dir.stat()?,
                InnerRepr::RegularFile(lite_file) => lite_file.stat()?,
                InnerRepr::Symlink(lite_symlink) => {
                    lite_symlink.stat(self.name_translator.as_ref())?
                }
            };

            Ok(stat_to_fileattr(&st)?)
        };

        match inner() {
            Ok(attr) => {
                log::trace!("getattr(_req={_req:?}, ino={ino:?}, fh={fh:?}) = (attr={attr:?})");
                reply.attr(&Duration::from_secs(30), &attr)
            }
            Err(err) => {
                log::trace!(
                    "getattr(_req={_req:?}, ino={ino:?}, fh={fh:?}) results in error {err:?}"
                );
                log::warn!("getattr(ino={ino:?}, fh={fh:?}) results in error {err:?}");
                reply.error(extract_errno(&err))
            }
        }
    }

    fn open(&mut self, _req: &fuser::Request<'_>, ino: u64, flags: i32, reply: fuser::ReplyOpen) {
        log::trace!("open(_req={_req:?}, ino={ino:?}, flags={flags:0x})");
        let inner = || -> anyhow::Result<u64> {
            let node = self.inode_table.lookup(ino).ok_or(Errno::NOENT)?;
            let mut inner = node
                .inner_repr
                .try_lock_for(MAX_LOCK_DURATION)
                .ok_or(Errno::DEADLOCK)?;
            let InnerRepr::RegularFile(lite_file) = &mut *inner else {
                return Err(Errno::NFILE)?;
            };
            let flags = rustix::fs::OFlags::from_bits_retain(flags.try_into()?);
            let readable = flags.contains(OFlags::RDONLY) || flags.contains(OFlags::RDWR);
            let writable = flags.contains(OFlags::WRONLY) || flags.contains(OFlags::RDWR);
            let appending = flags.contains(OFlags::APPEND);

            lite_file.upgrade_to_writable_fd(writable || appending, |fd: BorrowedFd<'_>| {
                Ok(reopen_as_writable(fd)?)
            })?;

            let descriptor: Box<LiteOpenedDescriptor> = Box::new(LiteOpenedDescriptor {
                inode: node.clone(),
                data: LiteOpenedData::OpenedFile {
                    readable: readable,
                    writable: writable,
                    appending: appending,
                },
            });

            Ok(Box::into_raw(descriptor) as u64)
        };

        match inner() {
            Ok(fh) => {
                log::trace!("open(_req={_req:?}, ino={ino:?}, flags={flags:0x}) = (fh={fh})");
                reply.opened(fh, flags as u32);
            }
            Err(err) => {
                log::trace!(
                    "open(_req={_req:?}, ino={ino:?}, flags={flags:0x}) results in error {err:?}"
                );
                log::warn!("open(ino={ino:?}, flags={flags:0x}) results in error {err:?}");
                reply.error(extract_errno(&err));
            }
        }
    }

    fn read(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        flags: i32,
        lock_owner: Option<u64>,
        reply: fuser::ReplyData,
    ) {
        log::trace!(
            "read(_req={_req:?}, ino={ino:?}, fh={fh:?}, offset={offset:?}, size={size:?}, flags={flags:0x}, lock_owner={lock_owner:?})"
        );
        let inner = || -> anyhow::Result<Vec<u8>> {
            let desc = unsafe { (fh as *mut LiteOpenedDescriptor).as_mut().unwrap() };
            let mut inner = desc
                .inode
                .inner_repr
                .try_lock_for(MAX_LOCK_DURATION)
                .ok_or(Errno::DEADLOCK)?;
            let InnerRepr::RegularFile(lite_file) = &mut *inner else {
                return Err(Errno::NFILE)?;
            };
            let LiteOpenedData::OpenedFile { readable, .. } = desc.data else {
                return Err(Errno::NFILE)?;
            };
            if !readable {
                return Err(Errno::PERM)?;
            }

            let mut result = vec![0u8; size.try_into()?];
            if lite_file
                .get_stream()
                .read(&mut result, offset.try_into()?)?
                != size.try_into()?
            {
                return Err(Errno::IO)?;
            }
            Ok(result)
        };

        match inner() {
            Ok(data) => {
                log::trace!(
                    "read(_req={_req:?}, ino={ino:?}, fh={fh:?}, offset={offset:?}, size={size:?}, flags={flags:0x}, lock_owner={lock_owner:?}) = (data.len={})\nData: {data:?}",
                    data.len()
                );
                reply.data(&data);
            }
            Err(err) => {
                log::trace!(
                    "read(_req={_req:?}, ino={ino:?}, fh={fh:?}, offset={offset:?}, size={size:?}, flags={flags:0x}, lock_owner={lock_owner:?}) results in error {err:?}"
                );
                log::trace!(
                    "read(ino={ino:?}, fh={fh:?}, offset={offset:?}, size={size:?}, flags={flags:0x}, lock_owner={lock_owner:?}) results in error {err:?}"
                );
                reply.error(extract_errno(&err));
            }
        }
    }

    fn write(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        write_flags: u32,
        flags: i32,
        lock_owner: Option<u64>,
        reply: fuser::ReplyWrite,
    ) {
        log::trace!(
            "write(_req={_req:?}, ino={ino:?}, fh={fh:?}, offset={offset:?}, data={data:?}, write_flags={write_flags:0x}, flags={flags:0x}, lock_owner={lock_owner:?})"
        );
        let inner = || -> anyhow::Result<u32> {
            let desc = unsafe { (fh as *mut LiteOpenedDescriptor).as_mut().unwrap() };
            let mut inner = desc
                .inode
                .inner_repr
                .try_lock_for(MAX_LOCK_DURATION)
                .ok_or(Errno::DEADLOCK)?;
            let InnerRepr::RegularFile(lite_file) = &mut *inner else {
                return Err(Errno::NFILE)?;
            };
            let LiteOpenedData::OpenedFile {
                writable,
                appending,
                ..
            } = desc.data
            else {
                return Err(Errno::NFILE)?;
            };
            if !writable || !appending {
                return Err(Errno::PERM)?;
            }

            let stream = lite_file.get_stream();
            stream.write(
                data,
                if appending {
                    stream.size()?.try_into()?
                } else {
                    offset.try_into()?
                },
            )?;
            Ok(data.len().try_into()?)
        };

        match inner() {
            Ok(size) => {
                log::trace!(
                    "write(_req={_req:?}, ino={ino:?}, fh={fh:?}, offset={offset:?}, data={data:?}, write_flags={write_flags:0x}, flags={flags:0x}, lock_owner={lock_owner:?}) = (size={size})"
                );
                reply.written(size);
            }
            Err(err) => {
                log::trace!(
                    "write(_req={_req:?}, ino={ino:?}, fh={fh:?}, offset={offset:?}, data={data:?}, write_flags={write_flags:0x}, flags={flags:0x}, lock_owner={lock_owner:?}) results in error {err:?}"
                );
                log::warn!(
                    "write(ino={ino:?}, fh={fh:?}, offset={offset:?}, write_flags={write_flags:0x}, flags={flags:0x}, lock_owner={lock_owner:?}) results in error {err:?}"
                );
                reply.error(extract_errno(&err));
            }
        }
    }

    fn release(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        flags: i32,
        lock_owner: Option<u64>,
        flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        log::trace!(
            "release(_req={_req:?}, ino={ino:?}, fh={fh:?}, flags={flags:0x}, lock_owner={lock_owner:?}, flush={flush:?})"
        );
        drop(unsafe { Box::from_raw(fh as *mut LiteOpenedDescriptor) });
        reply.ok();
    }
}

fn stat_to_fileattr(st: &rustix::fs::Stat) -> anyhow::Result<FileAttr> {
    Ok(FileAttr {
        ino: st.st_ino,
        size: st.st_size.try_into()?,
        blocks: (st.st_size / 512).try_into()?,
        atime: timespec_to_systemtime(st.st_atime, st.st_atime_nsec),
        mtime: timespec_to_systemtime(st.st_mtime, st.st_mtime_nsec),
        ctime: timespec_to_systemtime(st.st_ctime, st.st_ctime_nsec),
        crtime: timespec_to_systemtime(st.st_ctime, st.st_ctime_nsec),
        kind: filetype_from_mode(st.st_mode),
        perm: (st.st_mode & 0o7777) as u16,
        nlink: st.st_nlink.try_into()?,
        uid: st.st_uid,
        gid: st.st_gid,
        rdev: st.st_rdev.try_into()?,
        blksize: st.st_blksize.try_into()?,
        flags: 0,
    })
}

fn timespec_to_systemtime(tv_sec: i64, tv_nsec: u64) -> SystemTime {
    if tv_sec >= 0 {
        SystemTime::UNIX_EPOCH + Duration::new(tv_sec as u64, tv_nsec as u32)
    } else {
        SystemTime::UNIX_EPOCH - Duration::new(-tv_sec as u64, tv_nsec as u32)
    }
}

fn filetype_from_mode(mode: u32) -> fuser::FileType {
    match rustix::fs::FileType::from_raw_mode(mode) {
        rustix::fs::FileType::Directory => fuser::FileType::Directory,
        rustix::fs::FileType::RegularFile => fuser::FileType::RegularFile,
        rustix::fs::FileType::Symlink => fuser::FileType::Symlink,
        rustix::fs::FileType::BlockDevice => fuser::FileType::BlockDevice,
        rustix::fs::FileType::CharacterDevice => fuser::FileType::CharDevice,
        rustix::fs::FileType::Fifo => fuser::FileType::NamedPipe,
        rustix::fs::FileType::Socket => fuser::FileType::Socket,
        rustix::fs::FileType::Unknown => fuser::FileType::BlockDevice,
    }
}

fn extract_errno(e: &anyhow::Error) -> c_int {
    if let Some(errno) = e.downcast_ref::<rustix::io::Errno>() {
        return errno.raw_os_error();
    }
    if let Some(e) = e.downcast_ref::<std::io::Error>() {
        return e.raw_os_error().unwrap_or(Errno::IO.raw_os_error());
    }
    Errno::IO.raw_os_error()
}

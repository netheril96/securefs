#![cfg(feature = "fuse")]

use std::{
    f64::consts::E,
    ffi::c_int,
    mem::{replace, take},
    os::{
        fd::{AsFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    sync::atomic::{self, Ordering},
    time::{self, Duration, SystemTime},
};

use anyhow::anyhow;
use fuser::FileAttr;
use rustix::{
    fs::{Dir, Timespec},
    io::Errno,
};

use crate::{
    lite::vfs::{
        InnerRepr, IoWrapperStream, LiteDir, LiteFile, LiteSymlink, MAX_LOCK_DURATION, Vfs,
    },
    stream::lite::LiteAesGcmCryptStream,
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
                        child_repr.ensure_regular_file(|| {
                            let child_fd: OwnedFd = rustix::fs::openat(
                                parent_dir.as_fd(),
                                &enc_name,
                                rustix::fs::OFlags::RDONLY,
                                rustix::fs::Mode::empty(),
                            )?;
                            Ok(LiteFile::new(self.wrapper_opener.wrap(child_fd)?, false))
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
                reply.entry(&Duration::from_secs(30), &attr, generation);
            }
            Err(err) => reply.error(extract_errno(&err)),
        }
    }

    // fn getattr(
    //     &mut self,
    //     _req: &fuser::Request<'_>,
    //     ino: u64,
    //     fh: Option<u64>,
    //     reply: fuser::ReplyAttr,
    // ) {
    //     let inner = || -> anyhow::Result<FileAttr> {
    //         let node = self.inode_table.lookup(ino).ok_or(Errno::NOENT)?;
    //         let node = node
    //             .inner_repr
    //             .try_lock_for(MAX_LOCK_DURATION)
    //             .ok_or(Errno::DEADLOCK)?;
    //     };

    //     match inner() {
    //         Ok(attr) => reply.attr(&Duration::from_secs(30), &attr),
    //         Err(err) => reply.error(extract_errno(&err)),
    //     }
    // }
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

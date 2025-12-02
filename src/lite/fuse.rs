#![cfg(feature = "fuse")]
#![cfg(not(windows))]
use fuser::FileType;
use std::{
    ffi::c_int,
    os::{fd::AsFd, unix::ffi::OsStrExt},
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use fuser::{FUSE_ROOT_ID, FileAttr};
use once_cell::sync::OnceCell;
use rustix::io::Errno;

use crate::{
    lite::{
        IoWrapperFactory,
        name_translators::NameTranslator,
        unix::{LiteDirINode, LiteFileINode, LiteINode, LiteINodeHeader, LiteSymlinkINode},
    },
    vfs::unix::{Generation, INodeCore, INodeMetadata, INodeNumber},
};

pub struct FuseVfs {
    root_ino: INodeNumber,
    inode_table: dashmap::DashMap<INodeNumber, Arc<OnceCell<LiteINode>>>,
    name_translator: Arc<dyn NameTranslator>,
    wrapper_factory: Box<dyn IoWrapperFactory>,
    generation: AtomicU64,
    device_serial: OnceCell<u64>,
}

impl FuseVfs {
    fn ino_from_fuse(&self, ino: u64) -> INodeNumber {
        if ino == FUSE_ROOT_ID {
            self.root_ino
        } else if ino == self.root_ino.0 {
            INodeNumber(FUSE_ROOT_ID)
        } else {
            INodeNumber(ino)
        }
    }

    fn ino_to_fuse(&self, ino: INodeNumber) -> u64 {
        if ino == self.root_ino {
            FUSE_ROOT_ID
        } else if ino.0 == FUSE_ROOT_ID {
            self.root_ino.0
        } else {
            ino.0
        }
    }

    fn metadata_to_fileattr(&self, metadata: &INodeMetadata) -> anyhow::Result<FileAttr> {
        Ok(FileAttr {
            ino: self.ino_to_fuse(metadata.ino.try_into()?),
            size: metadata.size.try_into()?,
            blocks: metadata.blocks.try_into()?,
            atime: timespec_to_systemtime(
                metadata.atime.tv_sec,
                metadata.atime.tv_nsec.try_into()?,
            ),
            mtime: timespec_to_systemtime(
                metadata.mtime.tv_sec,
                metadata.mtime.tv_nsec.try_into()?,
            ),
            ctime: timespec_to_systemtime(
                metadata.ctime.tv_sec,
                metadata.ctime.tv_nsec.try_into()?,
            ),
            crtime: timespec_to_systemtime(
                metadata.crtime.tv_sec,
                metadata.crtime.tv_nsec.try_into()?,
            ),
            kind: mode_to_filetype(metadata.mode.try_into()?),
            perm: (metadata.mode & 0o777).try_into()?,
            nlink: metadata.nlink.try_into()?,
            uid: metadata.uid.try_into()?,
            gid: metadata.gid.try_into()?,
            rdev: metadata.rdev.try_into()?,
            blksize: metadata.blksize.try_into()?,
            flags: 0, // Not available in INodeMetadata
        })
    }
}

fn mode_to_filetype(mode: u32) -> FileType {
    match mode & libc::S_IFMT {
        libc::S_IFDIR => FileType::Directory,
        libc::S_IFREG => FileType::RegularFile,
        libc::S_IFLNK => FileType::Symlink,
        libc::S_IFBLK => FileType::BlockDevice,
        libc::S_IFCHR => FileType::CharDevice,
        libc::S_IFIFO => FileType::NamedPipe,
        libc::S_IFSOCK => FileType::Socket,
        _ => {
            // This should not happen
            log::warn!("Unknown file type with mode {mode:o}");
            FileType::RegularFile
        }
    }
}

impl fuser::Filesystem for FuseVfs {
    fn lookup(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        log::trace!("lookup(_req={_req:?}, parent={parent:?}, name={name:?})");
        let inner = || -> anyhow::Result<(FileAttr, u64)> {
            let parent_node = self
                .inode_table
                .get(&self.ino_from_fuse(parent))
                .ok_or(Errno::NOENT)?
                .value()
                .clone();
            let parent_node = parent_node.get().ok_or(Errno::NOENT)?;
            let LiteINode::LiteDirINode(parent_dir) = parent_node else {
                return Err(Errno::NOTDIR)?;
            };

            let enc_name = self.name_translator.encode_name(name.as_bytes())?;
            let mut stat = rustix::fs::statat(
                parent_dir.as_fd(),
                &enc_name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )?;
            if stat.st_dev as u64 != *self.device_serial.get_or_init(|| stat.st_dev as u64) {
                log::error!(
                    "The underlying filesystem must be on the same device, or securefs cannot obtain stable inode IDs."
                );
                return Err(Errno::IO)?;
            }

            let file_type = rustix::fs::FileType::from_raw_mode(stat.st_mode);
            match file_type {
                rustix::fs::FileType::Directory
                | rustix::fs::FileType::RegularFile
                | rustix::fs::FileType::Symlink => {}
                _ => return Err(Errno::NOENT)?,
            }

            let child_node = Arc::clone(
                self.inode_table
                    .entry(INodeNumber(stat.st_ino))
                    .or_insert_with(|| Arc::new(OnceCell::new()))
                    .value(),
            );
            // We need a separate statement to ensure `entry` call is dropped as soon as possible to reduce locking on the inode table.
            let child_node = child_node.get_or_try_init(|| -> anyhow::Result<LiteINode> {
                let header = LiteINodeHeader {
                    ino: INodeNumber(stat.st_ino),
                    generation: Generation(self.generation.load(Ordering::SeqCst)),
                    lookup_count: AtomicI64::new(0),
                    name_translator: self.name_translator.clone(),
                };
                Ok(match file_type {
                    rustix::fs::FileType::Directory => {
                        LiteDirINode::open(header, parent_dir.as_fd(), &enc_name)?.into()
                    }
                    rustix::fs::FileType::RegularFile => LiteFileINode::open(
                        header,
                        parent_dir.as_fd(),
                        &enc_name,
                        true,
                        self.wrapper_factory.as_ref(),
                    )?
                    .into(),
                    rustix::fs::FileType::Symlink => {
                        LiteSymlinkINode::open(header, parent_dir.as_fd(), &enc_name)?.into()
                    }
                    _ => unreachable!(),
                })
            })?;
            if let Some(sz) = child_node.maybe_size()? {
                stat.st_size = sz.try_into()?;
            }
            let metadata: INodeMetadata = stat.try_into()?;

            Ok((
                self.metadata_to_fileattr(&metadata)?,
                child_node.get_generation().0,
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

    // fn getattr(
    //     &mut self,
    //     _req: &fuser::Request<'_>,
    //     ino: u64,
    //     fh: Option<u64>,
    //     reply: fuser::ReplyAttr,
    // ) {
    //     log::trace!("getattr(_req={_req:?}, ino={ino:?}, fh={fh:?})");
    //     let inner = || -> anyhow::Result<FileAttr> { Ok(Default::default()) };

    //     match inner() {
    //         Ok(attr) => {
    //             log::trace!("getattr(_req={_req:?}, ino={ino:?}, fh={fh:?}) = (attr={attr:?})");
    //             reply.attr(&Duration::from_secs(30), &attr)
    //         }
    //         Err(err) => {
    //             log::trace!(
    //                 "getattr(_req={_req:?}, ino={ino:?}, fh={fh:?}) results in error {err:?}"
    //             );
    //             log::warn!("getattr(ino={ino:?}, fh={fh:?}) results in error {err:?}");
    //             reply.error(extract_errno(&err))
    //         }
    //     }
    // }

    // fn open(&mut self, _req: &fuser::Request<'_>, ino: u64, flags: i32, reply: fuser::ReplyOpen) {
    //     log::trace!("open(_req={_req:?}, ino={ino:?}, flags={flags:0x})");
    //     let inner = || -> anyhow::Result<u64> {
    //         let node = self.inode_table.lookup(ino).ok_or(Errno::NOENT)?;
    //         let mut inner = node
    //             .inner_repr
    //             .try_lock_for(MAX_LOCK_DURATION)
    //             .ok_or(Errno::DEADLK)?;
    //         let InnerRepr::RegularFile(lite_file) = &mut *inner else {
    //             return Err(Errno::NFILE)?;
    //         };
    //         let flags = rustix::fs::OFlags::from_bits_retain(flags.try_into()?);
    //         let readable = flags.contains(OFlags::RDONLY) || flags.contains(OFlags::RDWR);
    //         let writable = flags.contains(OFlags::WRONLY) || flags.contains(OFlags::RDWR);
    //         let appending = flags.contains(OFlags::APPEND);

    //         lite_file.upgrade_to_writable_fd(writable || appending, |fd: BorrowedFd<'_>| {
    //             Ok(reopen_as_writable(fd)?)
    //         })?;

    //         let descriptor: Box<LiteOpenedDescriptor> = Box::new(LiteOpenedDescriptor {
    //             inode: node.clone(),
    //             data: LiteOpenedData::OpenedFile {
    //                 readable: readable,
    //                 writable: writable,
    //                 appending: appending,
    //             },
    //         });

    //         Ok(Box::into_raw(descriptor) as u64)
    //     };

    //     match inner() {
    //         Ok(fh) => {
    //             log::trace!("open(_req={_req:?}, ino={ino:?}, flags={flags:0x}) = (fh={fh})");
    //             reply.opened(fh, flags as u32);
    //         }
    //         Err(err) => {
    //             log::trace!(
    //                 "open(_req={_req:?}, ino={ino:?}, flags={flags:0x}) results in error {err:?}"
    //             );
    //             log::warn!("open(ino={ino:?}, flags={flags:0x}) results in error {err:?}");
    //             reply.error(extract_errno(&err));
    //         }
    //     }
    // }

    // fn read(
    //     &mut self,
    //     _req: &fuser::Request<'_>,
    //     ino: u64,
    //     fh: u64,
    //     offset: i64,
    //     size: u32,
    //     flags: i32,
    //     lock_owner: Option<u64>,
    //     reply: fuser::ReplyData,
    // ) {
    //     log::trace!(
    //         "read(_req={_req:?}, ino={ino:?}, fh={fh:?}, offset={offset:?}, size={size:?}, flags={flags:0x}, lock_owner={lock_owner:?})"
    //     );
    //     let inner = || -> anyhow::Result<Vec<u8>> {
    //         let desc = unsafe { (fh as *mut LiteOpenedDescriptor).as_mut().unwrap() };
    //         let mut inner = desc
    //             .inode
    //             .inner_repr
    //             .try_lock_for(MAX_LOCK_DURATION)
    //             .ok_or(Errno::DEADLK)?;
    //         let InnerRepr::RegularFile(lite_file) = &mut *inner else {
    //             return Err(Errno::NFILE)?;
    //         };
    //         let LiteOpenedData::OpenedFile { readable, .. } = desc.data else {
    //             return Err(Errno::NFILE)?;
    //         };
    //         if !readable {
    //             return Err(Errno::PERM)?;
    //         }

    //         let mut result = vec![0u8; size.try_into()?];
    //         if lite_file
    //             .get_stream()
    //             .read(&mut result, offset.try_into()?)?
    //             != size.try_into()?
    //         {
    //             return Err(Errno::IO)?;
    //         }
    //         Ok(result)
    //     };

    //     match inner() {
    //         Ok(data) => {
    //             log::trace!(
    //                 "read(_req={_req:?}, ino={ino:?}, fh={fh:?}, offset={offset:?}, size={size:?}, flags={flags:0x}, lock_owner={lock_owner:?}) = (data.len={})\nData: {data:?}",
    //                 data.len()
    //             );
    //             reply.data(&data);
    //         }
    //         Err(err) => {
    //             log::trace!(
    //                 "read(_req={_req:?}, ino={ino:?}, fh={fh:?}, offset={offset:?}, size={size:?}, flags={flags:0x}, lock_owner={lock_owner:?}) results in error {err:?}"
    //             );
    //             log::trace!(
    //                 "read(ino={ino:?}, fh={fh:?}, offset={offset:?}, size={size:?}, flags={flags:0x}, lock_owner={lock_owner:?}) results in error {err:?}"
    //             );
    //             reply.error(extract_errno(&err));
    //         }
    //     }
    // }

    // fn write(
    //     &mut self,
    //     _req: &fuser::Request<'_>,
    //     ino: u64,
    //     fh: u64,
    //     offset: i64,
    //     data: &[u8],
    //     write_flags: u32,
    //     flags: i32,
    //     lock_owner: Option<u64>,
    //     reply: fuser::ReplyWrite,
    // ) {
    //     log::trace!(
    //         "write(_req={_req:?}, ino={ino:?}, fh={fh:?}, offset={offset:?}, data={data:?}, write_flags={write_flags:0x}, flags={flags:0x}, lock_owner={lock_owner:?})"
    //     );
    //     let inner = || -> anyhow::Result<u32> {
    //         let desc = unsafe { (fh as *mut LiteOpenedDescriptor).as_mut().unwrap() };
    //         let mut inner = desc
    //             .inode
    //             .inner_repr
    //             .try_lock_for(MAX_LOCK_DURATION)
    //             .ok_or(Errno::DEADLK)?;
    //         let InnerRepr::RegularFile(lite_file) = &mut *inner else {
    //             return Err(Errno::NFILE)?;
    //         };
    //         let LiteOpenedData::OpenedFile {
    //             writable,
    //             appending,
    //             ..
    //         } = desc.data
    //         else {
    //             return Err(Errno::NFILE)?;
    //         };
    //         if !writable || !appending {
    //             return Err(Errno::PERM)?;
    //         }

    //         let stream = lite_file.get_stream();
    //         stream.write(
    //             data,
    //             if appending {
    //                 stream.size()?.try_into()?
    //             } else {
    //                 offset.try_into()?
    //             },
    //         )?;
    //         Ok(data.len().try_into()?)
    //     };

    //     match inner() {
    //         Ok(size) => {
    //             log::trace!(
    //                 "write(_req={_req:?}, ino={ino:?}, fh={fh:?}, offset={offset:?}, data={data:?}, write_flags={write_flags:0x}, flags={flags:0x}, lock_owner={lock_owner:?}) = (size={size})"
    //             );
    //             reply.written(size);
    //         }
    //         Err(err) => {
    //             log::trace!(
    //                 "write(_req={_req:?}, ino={ino:?}, fh={fh:?}, offset={offset:?}, data={data:?}, write_flags={write_flags:0x}, flags={flags:0x}, lock_owner={lock_owner:?}) results in error {err:?}"
    //             );
    //             log::warn!(
    //                 "write(ino={ino:?}, fh={fh:?}, offset={offset:?}, write_flags={write_flags:0x}, flags={flags:0x}, lock_owner={lock_owner:?}) results in error {err:?}"
    //             );
    //             reply.error(extract_errno(&err));
    //         }
    //     }
    // }

    // fn release(
    //     &mut self,
    //     _req: &fuser::Request<'_>,
    //     ino: u64,
    //     fh: u64,
    //     flags: i32,
    //     lock_owner: Option<u64>,
    //     flush: bool,
    //     reply: fuser::ReplyEmpty,
    // ) {
    //     log::trace!(
    //         "release(_req={_req:?}, ino={ino:?}, fh={fh:?}, flags={flags:0x}, lock_owner={lock_owner:?}, flush={flush:?})"
    //     );
    //     // drop(unsafe { Box::from_raw(fh as *mut LiteOpenedDescriptor) });
    //     reply.ok();
    // }
}

fn timespec_to_systemtime(tv_sec: i64, tv_nsec: u32) -> SystemTime {
    if tv_sec >= 0 {
        SystemTime::UNIX_EPOCH + Duration::new(tv_sec as u64, tv_nsec)
    } else {
        SystemTime::UNIX_EPOCH - Duration::new(-tv_sec as u64, tv_nsec)
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

#![cfg(feature = "fuse")]
#![cfg(not(windows))]
use anyhow::Context;
use fuser::FileType;
use parking_lot::Mutex;
use std::{
    ffi::CString,
    os::{fd::AsFd, unix::ffi::OsStrExt},
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::{Duration, SystemTime},
};

use fuser::FUSE_ROOT_ID;
use once_cell::sync::OnceCell;
use rustix::io::Errno;

use crate::{
    fuse_wrappers::{
        bindings::{
            FUSE_CAP_HANDLE_KILLPRIV, FUSE_CAP_PARALLEL_DIROPS, FUSE_CAP_WRITEBACK_CACHE,
            fuse_entry_param,
        },
        fuse_low_level_ops::FuseLowLevelOps,
    },
    lite::{
        name_translators::NameTranslator,
        unix::{
            LiteDirINode, LiteFileINode, LiteINode, LiteINodeHeader, LiteSymlinkINode, LiteVfs,
        },
    },
    vfs::{
        GenericINodeTable, INodeNotFoundError,
        unix::{DirReader, Generation, INodeCore, INodeNumber},
    },
};

enum OpenedData {
    OpenedFile {
        readable: bool,
        writable: bool,
        appending: bool,
    },
    OpenedDir {
        reader: Mutex<Box<dyn DirReader>>,
    },
}

struct OpenedDescriptor {
    inode: Arc<OnceCell<LiteINode>>,
    data: OpenedData,
}

impl<Table: GenericINodeTable<LiteINode>> LiteVfs<Table> {
    fn ino_from_fuse(&self, ino: u64) -> INodeNumber {
        if ino == FUSE_ROOT_ID {
            self.inode_table.root_ino()
        } else if ino == self.inode_table.root_ino().0 {
            INodeNumber(FUSE_ROOT_ID)
        } else {
            INodeNumber(ino)
        }
    }

    fn ino_to_fuse(&self, ino: INodeNumber) -> u64 {
        if ino == self.inode_table.root_ino() {
            FUSE_ROOT_ID
        } else if ino.0 == FUSE_ROOT_ID {
            self.inode_table.root_ino().0
        } else {
            ino.0
        }
    }

    fn readjust_stat(&self, st: &mut rustix::fs::Stat) {
        st.st_ino = self.ino_to_fuse(INodeNumber(st.st_ino));
    }
}

fn mode_to_filetype(mode: libc::mode_t) -> FileType {
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

impl<Table: GenericINodeTable<LiteINode>> FuseLowLevelOps for LiteVfs<Table> {
    fn init(&mut self, conn: &mut crate::fuse_wrappers::bindings::fuse_conn_info) {
        conn.max_readahead = 1 << 24;
        conn.max_background = 32;
        conn.max_write = 1 << 24;
        conn.want |= FUSE_CAP_WRITEBACK_CACHE | FUSE_CAP_HANDLE_KILLPRIV | FUSE_CAP_PARALLEL_DIROPS;
    }

    fn can_lookup(&self) -> bool {
        true
    }

    fn lookup(
        &self,
        parent: crate::fuse_wrappers::bindings::fuse_ino_t,
        name: &std::ffi::CStr,
    ) -> anyhow::Result<crate::fuse_wrappers::bindings::fuse_entry_param> {
        let parent = self.inode_table.get(self.ino_from_fuse(parent));
        let parent = parent.unwrap()?;
        let LiteINode::LiteDirINode(parent) = parent else {
            return Err(Errno::NOTDIR)?;
        };
        let encoded_cname = CString::new(self.name_translator.encode_name(name.to_bytes())?)?;
        let mut st = rustix::fs::statat(
            parent.as_fd(),
            &encoded_cname,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )?;
        let child = self
            .inode_table
            .get_or_insert_default(INodeNumber(st.st_ino));
        let child = child.get_or_create(|| {
            let header = LiteINodeHeader {
                ino: INodeNumber(st.st_ino),
                generation: Generation(self.generation.load(Ordering::SeqCst)),
                lookup_count: AtomicI64::new(0),
                name_translator: self.name_translator.clone(),
            };
            match st.st_mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    Ok(
                        LiteDirINode::open(header, parent.as_fd(), encoded_cname.as_bytes())?
                            .into(),
                    )
                }

                libc::S_IFREG => Ok(LiteFileINode::open(
                    header,
                    parent.as_fd(),
                    encoded_cname.as_bytes(),
                    (st.st_mode & libc::S_IWUSR) != 0,
                    self.wrapper_factory.as_ref(),
                )?
                .into()),
                libc::S_IFLNK => {
                    Ok(LiteSymlinkINode::open(header, parent.as_fd(), encoded_cname)?.into())
                }
                _ => {
                    Err(Errno::PERM).with_context(|| format!("Unsupported st_mode {}", st.st_mode))
                }
            }
        })?;
        child.get_lookup_count().fetch_add(1, Ordering::SeqCst);
        child.readjust_stat(&mut st)?;
        self.readjust_stat(&mut st);

        Ok(fuse_entry_param {
            ino: self.ino_to_fuse(child.get_ino()),
            generation: child.get_generation().0,
            attr: unsafe { std::mem::transmute(st) },
            attr_timeout: self.attr_cache_duration.as_secs_f64(),
            entry_timeout: self.attr_cache_duration.as_secs_f64(),
        })
    }

    fn can_getattr(&self) -> bool {
        true
    }

    fn getattr(
        &self,
        ino: crate::fuse_wrappers::bindings::fuse_ino_t,
        fi: &mut crate::fuse_wrappers::bindings::fuse_file_info,
    ) -> anyhow::Result<(crate::fuse_wrappers::bindings::stat, f64)> {
        let common =
            |node: &LiteINode| -> anyhow::Result<(crate::fuse_wrappers::bindings::stat, f64)> {
                let mut st = node.get_metadata()?;
                self.readjust_stat(&mut st);
                Ok((
                    unsafe { std::mem::transmute(st) },
                    self.attr_cache_duration.as_secs_f64(),
                ))
            };

        if fi.fh != 0 {
            let desc = unsafe { (fi.fh as *mut OpenedDescriptor).as_mut().unwrap() };
            let node = desc
                .inode
                .get()
                .ok_or(INodeNotFoundError::INodeNotInitialized)?;
            common(node)
        } else {
            let ino = self.ino_from_fuse(ino);
            let node = self.inode_table.get(ino);
            let node = node.unwrap()?;
            common(node)
        }
    }
}

// impl fuser::Filesystem for FuseVfs {
//     fn lookup(
//         &mut self,
//         _req: &fuser::Request<'_>,
//         parent: u64,
//         name: &std::ffi::OsStr,
//         reply: fuser::ReplyEntry,
//     ) {
//         log::trace!("lookup(_req={_req:?}, parent={parent:?}, name={name:?})");
//         let inner = || -> anyhow::Result<(FileAttr, u64)> {
//             let parent_node = self.query_inode(parent)?;
//             let parent_node = parent_node.get().ok_or(Errno::NOENT)?;
//             let LiteINode::LiteDirINode(parent_dir) = parent_node else {
//                 return Err(Errno::NOTDIR)?;
//             };

//             let enc_name = self.name_translator.encode_name(name.as_bytes())?;
//             let mut stat = rustix::fs::statat(
//                 parent_dir.as_fd(),
//                 &enc_name,
//                 rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
//             )?;
//             if stat.st_dev as u64 != *self.device_serial.get_or_init(|| stat.st_dev as u64) {
//                 log::error!(
//                     "The underlying filesystem must be on the same device, or securefs cannot obtain stable inode IDs."
//                 );
//                 return Err(Errno::IO)?;
//             }

//             let file_type = rustix::fs::FileType::from_raw_mode(stat.st_mode);
//             match file_type {
//                 rustix::fs::FileType::Directory
//                 | rustix::fs::FileType::RegularFile
//                 | rustix::fs::FileType::Symlink => {}
//                 _ => return Err(Errno::NOENT)?,
//             }

//             let child_node = Arc::clone(
//                 self.inode_table
//                     .entry(INodeNumber(stat.st_ino))
//                     .or_insert_with(|| Arc::new(OnceCell::new()))
//                     .value(),
//             );
//             // We need a separate statement to ensure `entry` call is dropped as soon as possible to reduce locking on the inode table.
//             let child_node = child_node.get_or_try_init(|| -> anyhow::Result<LiteINode> {
//                 let header = LiteINodeHeader {
//                     ino: INodeNumber(stat.st_ino),
//                     generation: Generation(self.generation.load(Ordering::SeqCst)),
//                     lookup_count: AtomicI64::new(0),
//                     name_translator: self.name_translator.clone(),
//                 };
//                 Ok(match file_type {
//                     rustix::fs::FileType::Directory => {
//                         LiteDirINode::open(header, parent_dir.as_fd(), &enc_name)?.into()
//                     }
//                     rustix::fs::FileType::RegularFile => LiteFileINode::open(
//                         header,
//                         parent_dir.as_fd(),
//                         &enc_name,
//                         (stat.st_mode & libc::S_IWUSR) != 0,
//                         self.wrapper_factory.as_ref(),
//                     )?
//                     .into(),
//                     rustix::fs::FileType::Symlink => {
//                         LiteSymlinkINode::open(header, parent_dir.as_fd(), &enc_name)?.into()
//                     }
//                     _ => unreachable!(),
//                 })
//             })?;
//             if let Some(sz) = child_node.maybe_size()? {
//                 stat.st_size = sz.try_into()?;
//             }
//             let metadata: INodeMetadata = stat.try_into()?;

//             let result = Ok((
//                 self.metadata_to_fileattr(&metadata)?,
//                 child_node.get_generation().0,
//             ));
//             child_node.get_lookup_count().fetch_add(1, Ordering::SeqCst);
//             result
//         };
//         match inner() {
//             Ok((attr, generation)) => {
//                 log::trace!(
//                     "lookup(_req={_req:?}, parent={parent:?}, name={name:?}) = (attr={attr:?}, generation={generation})"
//                 );
//                 reply.entry(&self.attr_cache_duration, &attr, generation);
//             }
//             Err(err) => {
//                 log::trace!(
//                     "lookup(_req={_req:?}, parent={parent:?}, name={name:?}) results in error {err:?}"
//                 );
//                 log::warn!("lookup(parent={parent:?}, name={name:?}) results in error {err:?}");
//                 reply.error(extract_errno(&err));
//             }
//         }
//     }

//     fn getattr(
//         &mut self,
//         _req: &fuser::Request<'_>,
//         ino: u64,
//         fh: Option<u64>,
//         reply: fuser::ReplyAttr,
//     ) {
//         log::trace!("getattr(_req={_req:?}, ino={ino:?}, fh={fh:?})");
//         let inner = || -> anyhow::Result<FileAttr> {
//             match fh {
//                 Some(fh) => {
//                     let desc = unsafe { (fh as *mut OpenedDescriptor).as_mut().unwrap() };
//                     let meta = desc.inode.get().ok_or(Errno::NOENT)?.get_metadata()?;
//                     self.metadata_to_fileattr(&meta)
//                 }
//                 None => {
//                     let inode = self.query_inode(ino)?;
//                     let inode = inode.get().ok_or(Errno::NOENT)?;
//                     let meta = inode.get_metadata()?;
//                     self.metadata_to_fileattr(&meta)
//                 }
//             }
//         };

//         match inner() {
//             Ok(attr) => {
//                 log::trace!("getattr(_req={_req:?}, ino={ino:?}, fh={fh:?}) = (attr={attr:?})");
//                 reply.attr(&Duration::from_secs(30), &attr)
//             }
//             Err(err) => {
//                 log::trace!(
//                     "getattr(_req={_req:?}, ino={ino:?}, fh={fh:?}) results in error {err:?}"
//                 );
//                 log::warn!("getattr(ino={ino:?}, fh={fh:?}) results in error {err:?}");
//                 reply.error(extract_errno(&err))
//             }
//         }
//     }

//     fn create(
//         &mut self,
//         _req: &fuser::Request<'_>,
//         parent: u64,
//         name: &std::ffi::OsStr,
//         mode: u32,
//         umask: u32,
//         flags: i32,
//         reply: fuser::ReplyCreate,
//     ) {
//         let inner = || -> anyhow::Result<(u64, FileAttr, Generation)> {
//             let parent_node = self.query_inode(parent)?;
//             let parent_node = parent_node.get().ok_or(Errno::NOENT)?;
//             let LiteINode::LiteDirINode(parent_dir) = parent_node else {
//                 return Err(Errno::NOTDIR)?;
//             };

//             let enc_name = self.name_translator.encode_name(name.as_bytes())?;
//             let created_fd = rustix::fs::openat(
//                 parent_dir.as_fd(),
//                 &enc_name,
//                 OFlags::RDWR | OFlags::EXCL | OFlags::CREATE,
//                 Mode::from_raw_mode((mode & !umask) as libc::mode_t),
//             )?;
//             let stat = rustix::fs::fstat(created_fd.as_fd())?;

//             let child_node = Arc::clone(
//                 self.inode_table
//                     .entry(INodeNumber(stat.st_ino))
//                     .or_insert_with(|| Arc::new(OnceCell::new()))
//                     .value(),
//             );
//             let generation = Generation(self.generation.load(Ordering::SeqCst));
//             let _ = child_node.get_or_try_init(|| -> anyhow::Result<LiteINode> {
//                 let header = LiteINodeHeader {
//                     ino: INodeNumber(stat.st_ino),
//                     generation,
//                     lookup_count: AtomicI64::new(1),
//                     name_translator: self.name_translator.clone(),
//                 };
//                 Ok(LiteFileINode::new(header, self.wrapper_factory.wrap(created_fd)?, true).into())
//             })?;
//             let fh: Box<OpenedDescriptor> = Box::new(OpenedDescriptor {
//                 inode: child_node,
//                 data: OpenedData::OpenedFile {
//                     readable: true,
//                     writable: true,
//                     appending: false,
//                 },
//             });
//             Ok((
//                 Box::into_raw(fh) as u64,
//                 self.metadata_to_fileattr(&stat.try_into()?)?,
//                 generation,
//             ))
//         };

//         match inner() {
//             Ok((fh, fattr, generation)) => {
//                 reply.created(
//                     &self.attr_cache_duration,
//                     &fattr,
//                     generation.0,
//                     fh,
//                     flags as u32,
//                 );
//             }
//             Err(err) => {
//                 reply.error(extract_errno(&err));
//             }
//         }
//     }

//     fn open(&mut self, _req: &fuser::Request<'_>, ino: u64, flags: i32, reply: fuser::ReplyOpen) {
//         log::trace!("open(_req={_req:?}, ino={ino:?}, flags={flags:0x})");
//         let inner = || -> anyhow::Result<u64> {
//             let node = self.query_inode(ino)?;
//             let LiteINode::LiteFileINode(_) = node.get().ok_or(Errno::NOENT)? else {
//                 return Err(Errno::NFILE)?;
//             };

//             let flags = OFlags::from_bits_retain(flags.try_into()?);
//             let readable = flags.contains(OFlags::RDONLY) || flags.contains(OFlags::RDWR);
//             let writable = flags.contains(OFlags::WRONLY)
//                 || flags.contains(OFlags::RDWR)
//                 || flags.contains(OFlags::APPEND);
//             let appending = flags.contains(OFlags::APPEND);

//             let descriptor = Box::new(OpenedDescriptor {
//                 inode: node.clone(),
//                 data: OpenedData::OpenedFile {
//                     readable,
//                     writable,
//                     appending,
//                 },
//             });

//             Ok(Box::into_raw(descriptor) as u64)
//         };

//         match inner() {
//             Ok(fh) => {
//                 log::trace!("open(_req={_req:?}, ino={ino:?}, flags={flags:0x}) = (fh={fh})");
//                 reply.opened(fh, flags as u32);
//             }
//             Err(err) => {
//                 log::trace!(
//                     "open(_req={_req:?}, ino={ino:?}, flags={flags:0x}) results in error {err:?}"
//                 );
//                 log::warn!("open(ino={ino:?}, flags={flags:0x}) results in error {err:?}");
//                 reply.error(extract_errno(&err));
//             }
//         }
//     }

//     fn read(
//         &mut self,
//         _req: &fuser::Request<'_>,
//         ino: u64,
//         fh: u64,
//         offset: i64,
//         size: u32,
//         flags: i32,
//         lock_owner: Option<u64>,
//         reply: fuser::ReplyData,
//     ) {
//         log::trace!(
//             "read(_req={_req:?}, ino={ino:?}, fh={fh:?}, offset={offset:?}, size={size:?}, flags={flags:0x}, lock_owner={lock_owner:?})"
//         );
//         let inner = || -> anyhow::Result<Vec<u8>> {
//             let desc = unsafe { (fh as *mut OpenedDescriptor).as_mut().unwrap() };
//             let LiteINode::LiteFileINode(file) = desc.inode.get().ok_or(Errno::BADF)? else {
//                 return Err(Errno::NFILE)?;
//             };

//             let OpenedData::OpenedFile { readable, .. } = desc.data else {
//                 return Err(Errno::NFILE)?;
//             };
//             if !readable {
//                 return Err(Errno::PERM)?;
//             }

//             let mut result = vec![0u8; size.try_into()?];
//             if file.read(&mut result, offset.try_into()?)? != size.try_into()? {
//                 return Err(Errno::IO)?;
//             }
//             Ok(result)
//         };

//         match inner() {
//             Ok(data) => {
//                 log::trace!(
//                     "read(_req={_req:?}, ino={ino:?}, fh={fh:?}, offset={offset:?}, size={size:?}, flags={flags:0x}, lock_owner={lock_owner:?}) = (data.len={})\nData: {data:?}",
//                     data.len()
//                 );
//                 reply.data(&data);
//             }
//             Err(err) => {
//                 log::trace!(
//                     "read(_req={_req:?}, ino={ino:?}, fh={fh:?}, offset={offset:?}, size={size:?}, flags={flags:0x}, lock_owner={lock_owner:?}) results in error {err:?}"
//                 );
//                 log::trace!(
//                     "read(ino={ino:?}, fh={fh:?}, offset={offset:?}, size={size:?}, flags={flags:0x}, lock_owner={lock_owner:?}) results in error {err:?}"
//                 );
//                 reply.error(extract_errno(&err));
//             }
//         }
//     }

//     fn write(
//         &mut self,
//         _req: &fuser::Request<'_>,
//         ino: u64,
//         fh: u64,
//         offset: i64,
//         data: &[u8],
//         write_flags: u32,
//         flags: i32,
//         lock_owner: Option<u64>,
//         reply: fuser::ReplyWrite,
//     ) {
//         log::trace!(
//             "write(_req={_req:?}, ino={ino:?}, fh={fh:?}, offset={offset:?}, data={data:?}, write_flags={write_flags:0x}, flags={flags:0x}, lock_owner={lock_owner:?})"
//         );
//         let inner = || -> anyhow::Result<u32> {
//             let desc = unsafe { (fh as *mut OpenedDescriptor).as_mut().unwrap() };
//             let LiteINode::LiteFileINode(file) = desc.inode.get().ok_or(Errno::BADF)? else {
//                 return Err(Errno::NFILE)?;
//             };

//             let OpenedData::OpenedFile {
//                 writable,
//                 appending,
//                 ..
//             } = desc.data
//             else {
//                 return Err(Errno::NFILE)?;
//             };
//             if !writable && !appending {
//                 return Err(Errno::PERM)?;
//             }

//             if appending {
//                 file.append(data)?;
//             } else {
//                 file.write(data, offset.try_into()?)?;
//             }
//             Ok(data.len().try_into()?)
//         };

//         match inner() {
//             Ok(size) => {
//                 log::trace!(
//                     "write(_req={_req:?}, ino={ino:?}, fh={fh:?}, offset={offset:?}, data={data:?}, write_flags={write_flags:0x}, flags={flags:0x}, lock_owner={lock_owner:?}) = (size={size})"
//                 );
//                 reply.written(size);
//             }
//             Err(err) => {
//                 log::trace!(
//                     "write(_req={_req:?}, ino={ino:?}, fh={fh:?}, offset={offset:?}, data={data:?}, write_flags={write_flags:0x}, flags={flags:0x}, lock_owner={lock_owner:?}) results in error {err:?}"
//                 );
//                 log::warn!(
//                     "write(ino={ino:?}, fh={fh:?}, offset={offset:?}, write_flags={write_flags:0x}, flags={flags:0x}, lock_owner={lock_owner:?}) results in error {err:?}"
//                 );
//                 reply.error(extract_errno(&err));
//             }
//         }
//     }

//     fn release(
//         &mut self,
//         _req: &fuser::Request<'_>,
//         ino: u64,
//         fh: u64,
//         flags: i32,
//         lock_owner: Option<u64>,
//         flush: bool,
//         reply: fuser::ReplyEmpty,
//     ) {
//         log::trace!(
//             "release(_req={_req:?}, ino={ino:?}, fh={fh:?}, flags={flags:0x}, lock_owner={lock_owner:?}, flush={flush:?})"
//         );
//         drop(unsafe { Box::from_raw(fh as *mut OpenedDescriptor) });
//         reply.ok();
//     }

//     fn forget(&mut self, _req: &fuser::Request<'_>, _ino: u64, _nlookup: u64) {
//         self.inode_table
//             .remove_if(&self.ino_from_fuse(_ino), |_, v| {
//                 let Some(node) = v.get() else {
//                     return true;
//                 };
//                 node.get_lookup_count()
//                     .fetch_sub(_nlookup as i64, Ordering::SeqCst)
//                     <= _nlookup as i64
//             });
//     }
// }

fn timespec_to_systemtime(tv_sec: i64, tv_nsec: u32) -> SystemTime {
    if tv_sec >= 0 {
        SystemTime::UNIX_EPOCH + Duration::new(tv_sec as u64, tv_nsec)
    } else {
        SystemTime::UNIX_EPOCH - Duration::new(-tv_sec as u64, tv_nsec)
    }
}

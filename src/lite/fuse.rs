#![cfg(feature = "fuse")]
#![cfg(not(windows))]
use anyhow::Context;
use fuser::FileType;
use parking_lot::Mutex;
use std::{
    ffi::CString,
    fs::DirEntry,
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
            fuse_add_direntry, fuse_entry_param,
        },
        fuse_low_level_ops::{FuseLowLevelOps, FuseReq},
    },
    lite::{
        name_translators::NameTranslator,
        unix::{
            LiteDirINode, LiteDirReader, LiteFileINode, LiteINode, LiteINodeHeader,
            LiteSymlinkINode, LiteVfs,
        },
    },
    vfs::{
        GenericINodeTable, INodeNotFoundError,
        unix::{DirINodeExt, DirReader, FileINodeExt, Generation, INodeCore, INodeNumber},
    },
};

enum OpenedData {
    OpenedFile {
        readable: bool,
        writable: bool,
        appending: bool,
    },
    OpenedDir {
        reader: Mutex<LiteDirReader>,
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
        _req: FuseReq,
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
        _req: FuseReq,
        ino: crate::fuse_wrappers::bindings::fuse_ino_t,
        fi: &crate::fuse_wrappers::bindings::fuse_file_info,
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

    fn can_create(&self) -> bool {
        !self.readonly
    }

    fn create(
        &self,
        _req: FuseReq,
        parent: crate::fuse_wrappers::bindings::fuse_ino_t,
        name: &std::ffi::CStr,
        mode: crate::fuse_wrappers::bindings::mode_t,
        fi: &crate::fuse_wrappers::bindings::fuse_file_info,
    ) -> anyhow::Result<(
        crate::fuse_wrappers::bindings::fuse_entry_param,
        crate::fuse_wrappers::bindings::fuse_file_info,
    )> {
        let parent_node = self.inode_table.get(self.ino_from_fuse(parent));
        let parent_node = parent_node.unwrap()?;
        let LiteINode::LiteDirINode(parent_dir) = parent_node else {
            return Err(Errno::NOTDIR)?;
        };

        let encoded_name = self.name_translator.encode_name(name.to_bytes())?;
        let created_fd = rustix::fs::openat(
            parent_dir.as_fd(),
            &encoded_name,
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::EXCL,
            rustix::fs::Mode::from_raw_mode(mode),
        )?;

        let mut stat = rustix::fs::fstat(&created_fd)?;
        let ino = INodeNumber(stat.st_ino);
        let generation = Generation(self.generation.load(Ordering::SeqCst));

        let child_node = self.inode_table.get_or_insert_default(ino);
        let child_node_ref = child_node.get_or_create(|| {
            let header = LiteINodeHeader {
                ino,
                generation,
                lookup_count: AtomicI64::new(1),
                name_translator: self.name_translator.clone(),
            };
            Ok(LiteFileINode::new(header, self.wrapper_factory.wrap(created_fd)?, true).into())
        })?;
        child_node_ref.readjust_stat(&mut stat)?;

        let fh = Box::new(OpenedDescriptor {
            inode: child_node.0.clone(),
            data: OpenedData::OpenedFile {
                readable: true,
                writable: true,
                appending: false,
            },
        });

        self.readjust_stat(&mut stat);
        let entry = fuse_entry_param {
            ino: stat.st_ino,
            generation: generation.0,
            attr: unsafe { std::mem::transmute(stat) },
            attr_timeout: self.attr_cache_duration.as_secs_f64(),
            entry_timeout: self.attr_cache_duration.as_secs_f64(),
        };
        let mut new_fi = *fi;
        new_fi.fh = Box::into_raw(fh) as u64;
        Ok((entry, new_fi))
    }

    fn can_open(&self) -> bool {
        true
    }

    fn open(
        &self,
        _req: FuseReq,
        ino: crate::fuse_wrappers::bindings::fuse_ino_t,
        fi: &crate::fuse_wrappers::bindings::fuse_file_info,
    ) -> anyhow::Result<crate::fuse_wrappers::bindings::fuse_file_info> {
        let node = self.inode_table.get(self.ino_from_fuse(ino));
        let opened_data = {
            let n = node.unwrap()?;
            match n {
                LiteINode::LiteFileINode(_) => {
                    let flags = rustix::fs::OFlags::from_bits_retain(fi.flags as _);
                    let readable = flags.contains(rustix::fs::OFlags::RDONLY)
                        || flags.contains(rustix::fs::OFlags::RDWR);
                    let writable = flags.contains(rustix::fs::OFlags::WRONLY)
                        || flags.contains(rustix::fs::OFlags::RDWR)
                        || flags.contains(rustix::fs::OFlags::APPEND);
                    let appending = flags.contains(rustix::fs::OFlags::APPEND);
                    OpenedData::OpenedFile {
                        readable,
                        writable,
                        appending,
                    }
                }
                _ => return Err(Errno::INVAL)?,
            }
        };

        let descriptor = Box::new(OpenedDescriptor {
            inode: node.0.expect("already checked"),
            data: opened_data,
        });
        let mut new_fi = *fi;
        new_fi.fh = Box::into_raw(descriptor) as u64;
        Ok(new_fi)
    }

    fn can_read(&self) -> bool {
        true
    }

    fn read(
        &self,
        _req: FuseReq,
        _ino: crate::fuse_wrappers::bindings::fuse_ino_t,
        size: usize,
        off: crate::fuse_wrappers::bindings::off_t,
        fi: &crate::fuse_wrappers::bindings::fuse_file_info,
    ) -> anyhow::Result<Vec<u8>> {
        let desc = unsafe { (fi.fh as *mut OpenedDescriptor).as_mut().unwrap() };
        let LiteINode::LiteFileINode(file) = desc.inode.get().ok_or(Errno::BADF)? else {
            return Err(Errno::INVAL)?;
        };

        let OpenedData::OpenedFile { readable, .. } = desc.data else {
            return Err(Errno::INVAL)?;
        };
        if !readable {
            return Err(Errno::PERM)?;
        }

        let mut result = vec![0u8; size];
        let read_size = file.read(&mut result, off.try_into()?)?;
        result.truncate(read_size);
        Ok(result)
    }

    fn can_write(&self) -> bool {
        !self.readonly
    }

    fn write(
        &self,
        _req: FuseReq,
        _ino: crate::fuse_wrappers::bindings::fuse_ino_t,
        buf: &[u8],
        off: crate::fuse_wrappers::bindings::off_t,
        fi: &crate::fuse_wrappers::bindings::fuse_file_info,
    ) -> anyhow::Result<usize> {
        let desc = unsafe { (fi.fh as *mut OpenedDescriptor).as_mut().unwrap() };
        let LiteINode::LiteFileINode(file) = desc.inode.get().ok_or(Errno::BADF)? else {
            return Err(Errno::INVAL)?;
        };

        let OpenedData::OpenedFile {
            writable,
            appending,
            ..
        } = desc.data
        else {
            return Err(Errno::INVAL)?;
        };
        if !writable && !appending {
            return Err(Errno::PERM)?;
        }

        if appending {
            file.append(buf)?;
        } else {
            file.write(buf, off as u64)?;
        }

        Ok(buf.len())
    }

    fn can_release(&self) -> bool {
        true
    }

    fn release(
        &self,
        _req: FuseReq,
        _ino: crate::fuse_wrappers::bindings::fuse_ino_t,
        fi: &crate::fuse_wrappers::bindings::fuse_file_info,
    ) -> anyhow::Result<()> {
        if fi.fh != 0 {
            drop(unsafe { Box::from_raw(fi.fh as *mut OpenedDescriptor) });
        }
        Ok(())
    }

    fn can_opendir(&self) -> bool {
        true
    }

    fn opendir(
        &self,
        _req: FuseReq,
        ino: crate::fuse_wrappers::bindings::fuse_ino_t,
        fi: &crate::fuse_wrappers::bindings::fuse_file_info,
    ) -> anyhow::Result<crate::fuse_wrappers::bindings::fuse_file_info> {
        let node = self.inode_table.get(self.ino_from_fuse(ino));
        let opened_data = {
            let n = node.unwrap()?;
            match n {
                LiteINode::LiteDirINode(dir) => OpenedData::OpenedDir {
                    reader: Mutex::new(dir.create_dir_reader()?),
                },
                _ => return Err(Errno::INVAL)?,
            }
        };

        let descriptor = Box::new(OpenedDescriptor {
            inode: node.0.expect("already checked"),
            data: opened_data,
        });
        let mut new_fi = *fi;
        new_fi.fh = Box::into_raw(descriptor) as u64;
        Ok(new_fi)
    }

    fn can_readdir(&self) -> bool {
        true
    }

    fn readdir(
        &self,
        mut req: FuseReq,
        _ino: crate::fuse_wrappers::bindings::fuse_ino_t,
        size: usize,
        off: crate::fuse_wrappers::bindings::off_t,
        fi: &crate::fuse_wrappers::bindings::fuse_file_info,
    ) -> anyhow::Result<Vec<u8>> {
        if fi.fh == 0 {
            return Err(Errno::BADF)?;
        }

        let mut buffer = vec![0u8; size];

        let desc = unsafe { (fi.fh as *mut OpenedDescriptor).as_mut().unwrap() };
        let OpenedData::OpenedDir { reader } = &mut desc.data else {
            return Err(Errno::NOTDIR)?;
        };

        let mut reader = reader.lock();
        if off == 0 && reader.current_position() != 0 {
            reader.rewind()?;
        } else if off != reader.current_position() {
            return Err(Errno::INVAL).with_context(
                || format!("expecting a pagination request for readdir at offset {}, got arbitrary seek at offset {}",
                     reader.current_position(), off));
        }

        loop {
            if !reader.move_next()? {
                break;
            }
            let entry = reader.current().unwrap();
            let name = CString::new(entry.name.clone())?;
            let mut st: crate::fuse_wrappers::bindings::stat = unsafe { std::mem::zeroed() };
            st.st_ino = self.ino_to_fuse(entry.ino);
            //st.st_mode = (entry.filetype.to_s_if() | 0o555) as _;
            if !req.add_dir_entry(&mut buffer, &name, &st, entry.offset) {
                break;
            }
        }
        Ok(buffer)
    }

    fn can_releasedir(&self) -> bool {
        true
    }

    fn releasedir(
        &self,
        req: FuseReq,
        ino: crate::fuse_wrappers::bindings::fuse_ino_t,
        fi: &crate::fuse_wrappers::bindings::fuse_file_info,
    ) -> anyhow::Result<()> {
        return self.release(req, ino, fi);
    }
}

fn timespec_to_systemtime(tv_sec: i64, tv_nsec: u32) -> SystemTime {
    if tv_sec >= 0 {
        SystemTime::UNIX_EPOCH + Duration::new(tv_sec as u64, tv_nsec)
    } else {
        SystemTime::UNIX_EPOCH - Duration::new(-tv_sec as u64, tv_nsec)
    }
}

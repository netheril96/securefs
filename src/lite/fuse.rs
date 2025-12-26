#![cfg(feature = "fuse")]
#![cfg(not(windows))]
use anyhow::Context;
use parking_lot::Mutex;
use std::{
    ffi::CString,
    os::fd::AsFd,
    sync::atomic::{AtomicI64, Ordering},
    time::{Duration, SystemTime},
};

use rustix::{
    fs::{AtFlags, Mode, OFlags},
    io::Errno,
};

use crate::{
    fuse_wrappers::{
        bindings::{
            FUSE_CAP_HANDLE_KILLPRIV, FUSE_CAP_PARALLEL_DIROPS, FUSE_CAP_WRITEBACK_CACHE,
            FUSE_ROOT_ID, fuse_entry_param,
        },
        fuse_low_level_ops::{FuseLowLevelOps, FuseReq},
    },
    lite::{
        IoWrapperFactory,
        long_name_db::C_LONG_NAME_DB_FILENAME,
        unix::{
            LiteDirINode, LiteDirReader, LiteFileINode, LiteINode, LiteINodeHeader,
            LiteSymlinkINode, LiteVfs, ReadjustStatExt,
        },
    },
    tearc::Tearc,
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
    inode: Tearc<LiteINode>,
    data: OpenedData,
}

impl<Table: GenericINodeTable<LiteINode>> LiteVfs<Table> {
    fn ino_from_fuse(&self, ino: u64) -> INodeNumber {
        if ino == FUSE_ROOT_ID.into() {
            self.inode_table.root_ino()
        } else if ino == self.inode_table.root_ino().0 {
            INodeNumber(FUSE_ROOT_ID.into())
        } else {
            INodeNumber(ino)
        }
    }

    fn ino_to_fuse(&self, ino: INodeNumber) -> u64 {
        if ino == self.inode_table.root_ino() {
            FUSE_ROOT_ID.into()
        } else if ino.0 == FUSE_ROOT_ID.into() {
            self.inode_table.root_ino().0
        } else {
            ino.0
        }
    }

    fn readjust_stat(&self, st: &mut rustix::fs::Stat) {
        st.st_ino = self.ino_to_fuse(INodeNumber(st.st_ino));
    }

    fn release_common(
        fi: Option<&crate::fuse_wrappers::bindings::fuse_file_info>,
    ) -> anyhow::Result<()> {
        let fi = fi.ok_or(Errno::BADF)?;
        if fi.fh != 0 {
            drop(unsafe { Box::from_raw(fi.fh as *mut OpenedDescriptor) });
        }
        Ok(())
    }
}

impl<Table: GenericINodeTable<LiteINode>> FuseLowLevelOps for LiteVfs<Table> {
    fn init(
        &mut self,
        mut conn: crate::fuse_wrappers::bindings::fuse_conn_info,
    ) -> crate::fuse_wrappers::bindings::fuse_conn_info {
        conn.max_readahead = 1 << 20;
        conn.max_background = 32;
        conn.max_write = 1 << 20;
        if conn.capable & FUSE_CAP_WRITEBACK_CACHE != 0 {
            conn.want |= FUSE_CAP_WRITEBACK_CACHE
        }
        if conn.capable & FUSE_CAP_HANDLE_KILLPRIV != 0 {
            conn.want |= FUSE_CAP_HANDLE_KILLPRIV
        }
        if conn.capable & FUSE_CAP_PARALLEL_DIROPS != 0 {
            conn.want |= FUSE_CAP_PARALLEL_DIROPS
        }
        conn
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
        let parent = self
            .inode_table
            .get(self.ino_from_fuse(parent))
            .ok_or(INodeNotFoundError::INodeNotInTable)?;
        let LiteINode::LiteDirINode(parent) = &*parent else {
            return Err(Errno::NOTDIR)?;
        };
        let encoded_cname = CString::new(self.name_translator.encode_name(name.to_bytes())?)?;
        let mut st = rustix::fs::statat(
            parent.as_fd(),
            &encoded_cname,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )?;
        if st.st_dev != self.device_serial {
            return Err(Errno::PERM).with_context(|| {
                format!(
                    concat!(
                        "securefs lite format expects that the underlying ",
                        "repostiory is on the same filesystem and have stable inode numbers, ",
                        "but the root dir has device {} while child has {}"
                    ),
                    self.device_serial, st.st_dev
                )
            });
        }
        let child = self
            .inode_table
            .get_or_try_insert_with(INodeNumber(st.st_ino), || {
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
                        !self.readonly && (st.st_mode & libc::S_IWUSR) != 0,
                        &self.wrapper_factory,
                    )?
                    .into()),
                    libc::S_IFLNK => {
                        Ok(LiteSymlinkINode::open(header, parent.as_fd(), encoded_cname)?.into())
                    }
                    _ => Err(Errno::PERM)
                        .with_context(|| format!("Unsupported st_mode {}", st.st_mode))?,
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
        fi: Option<&crate::fuse_wrappers::bindings::fuse_file_info>,
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

        if let Some(fi) = fi.filter(|fi| fi.fh != 0) {
            let desc = unsafe { &mut *(fi.fh as *mut OpenedDescriptor) };
            common(&desc.inode)
        } else {
            let ino = self.ino_from_fuse(ino);
            let node = self
                .inode_table
                .get(ino)
                .ok_or(INodeNotFoundError::INodeNotInTable)?;
            common(&node)
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
        fi: Option<&crate::fuse_wrappers::bindings::fuse_file_info>,
    ) -> anyhow::Result<(
        crate::fuse_wrappers::bindings::fuse_entry_param,
        crate::fuse_wrappers::bindings::fuse_file_info,
    )> {
        let parent_node = self
            .inode_table
            .get(self.ino_from_fuse(parent))
            .ok_or(INodeNotFoundError::INodeNotInTable)?;
        let LiteINode::LiteDirINode(parent_dir) = &*parent_node else {
            return Err(Errno::NOTDIR)?;
        };

        let encoded_name = self.name_translator.encode_name(name.to_bytes())?;

        if self.name_translator.is_long_name(&encoded_name) {
            let encrypted_name = self.name_translator.encrypt_name(name.to_bytes())?;
            let table = parent_dir.ensure_writable_long_name_db()?;
            table.update_mapping(encoded_name.as_slice(), encrypted_name.as_slice())?;
        }

        let created_fd = rustix::fs::openat(
            parent_dir.as_fd(),
            &encoded_name,
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::EXCL,
            rustix::fs::Mode::from_raw_mode(mode),
        )?;

        let mut stat = rustix::fs::fstat(&created_fd)?;
        let ino = INodeNumber(stat.st_ino);
        let generation = Generation(self.generation.load(Ordering::SeqCst));

        let child_node = self.inode_table.get_or_try_insert_with(ino, || {
            let header = LiteINodeHeader {
                ino,
                generation,
                lookup_count: AtomicI64::new(1),
                name_translator: self.name_translator.clone(),
            };
            Ok(LiteFileINode::new(header, self.wrapper_factory.wrap(created_fd)?, true).into())
        })?;
        child_node.readjust_stat(&mut stat)?;

        let fh = Box::new(OpenedDescriptor {
            inode: child_node,
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
        let mut new_fi = fi.copied().unwrap_or_else(|| unsafe { std::mem::zeroed() });
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
        fi: Option<&crate::fuse_wrappers::bindings::fuse_file_info>,
    ) -> anyhow::Result<crate::fuse_wrappers::bindings::fuse_file_info> {
        let node = self
            .inode_table
            .get(self.ino_from_fuse(ino))
            .ok_or(INodeNotFoundError::INodeNotInTable)?;
        let opened_data = {
            match &*node {
                LiteINode::LiteFileINode(_) => {
                    let fi = fi.ok_or(Errno::INVAL)?;
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
            inode: node,
            data: opened_data,
        });
        let mut new_fi = fi.copied().unwrap_or_else(|| unsafe { std::mem::zeroed() });
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
        fi: Option<&crate::fuse_wrappers::bindings::fuse_file_info>,
    ) -> anyhow::Result<Vec<u8>> {
        let fi = fi.ok_or(Errno::BADF)?;
        let desc = unsafe { &mut *(fi.fh as *mut OpenedDescriptor) };
        let LiteINode::LiteFileINode(file) = &*desc.inode else {
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
        fi: Option<&crate::fuse_wrappers::bindings::fuse_file_info>,
    ) -> anyhow::Result<usize> {
        let fi = fi.ok_or(Errno::BADF)?;
        let desc = unsafe { &mut *(fi.fh as *mut OpenedDescriptor) };
        let LiteINode::LiteFileINode(file) = &*desc.inode else {
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
        fi: Option<&crate::fuse_wrappers::bindings::fuse_file_info>,
    ) -> anyhow::Result<()> {
        Self::release_common(fi)
    }

    fn can_opendir(&self) -> bool {
        true
    }

    fn opendir(
        &self,
        _req: FuseReq,
        ino: crate::fuse_wrappers::bindings::fuse_ino_t,
        fi: Option<&crate::fuse_wrappers::bindings::fuse_file_info>,
    ) -> anyhow::Result<crate::fuse_wrappers::bindings::fuse_file_info> {
        let node = self
            .inode_table
            .get(self.ino_from_fuse(ino))
            .ok_or(INodeNotFoundError::INodeNotInTable)?;
        let dir_node = Tearc::try_map_or_err(node.clone(), |n| match n {
            LiteINode::LiteDirINode(dir) => Ok(dir),
            _ => Err(Errno::NOTDIR),
        })?;
        let opened_data = OpenedData::OpenedDir {
            reader: Mutex::new(LiteDirINode::create_dir_reader(dir_node)?),
        };

        let descriptor = Box::new(OpenedDescriptor {
            inode: node,
            data: opened_data,
        });
        let mut new_fi = fi.copied().unwrap_or_else(|| unsafe { std::mem::zeroed() });
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
        fi: Option<&crate::fuse_wrappers::bindings::fuse_file_info>,
    ) -> anyhow::Result<Vec<u8>> {
        let fi = fi.ok_or(Errno::BADF)?;
        if fi.fh == 0 {
            return Err(Errno::BADF)?;
        }

        let mut buffer = vec![0u8; size];

        let desc = unsafe { &mut *(fi.fh as *mut OpenedDescriptor) };
        let OpenedData::OpenedDir { reader } = &mut desc.data else {
            return Err(Errno::NOTDIR)?;
        };

        let mut reader = reader.lock();

        let mut written_size: usize = 0;

        reader.iterate_from(off, |entry| {
            let mut st: crate::fuse_wrappers::bindings::stat = unsafe { std::mem::zeroed() };

            let name = CString::new(entry.name)?;
            st.st_ino = self.ino_to_fuse(entry.ino);
            st.st_mode = match entry.filetype {
                crate::vfs::unix::FileType::DIRECTORY => libc::S_IFDIR,
                crate::vfs::unix::FileType::FILE => libc::S_IFREG,
                crate::vfs::unix::FileType::SYMLINK => libc::S_IFLNK,
            };

            written_size = buffer.len().min(
                written_size
                    + req.add_dir_entry(&mut buffer[written_size..], &name, &st, entry.offset),
            );
            if written_size >= buffer.len() {
                return Ok(false);
            }
            Ok(true)
        })?;
        buffer.truncate(written_size);
        Ok(buffer)
    }

    fn can_releasedir(&self) -> bool {
        true
    }

    fn releasedir(
        &self,
        _req: FuseReq,
        _ino: crate::fuse_wrappers::bindings::fuse_ino_t,
        fi: Option<&crate::fuse_wrappers::bindings::fuse_file_info>,
    ) -> anyhow::Result<()> {
        Self::release_common(fi)
    }

    fn can_forget(&self) -> bool {
        true
    }

    fn forget(
        &self,
        req: FuseReq,
        ino: crate::fuse_wrappers::bindings::fuse_ino_t,
        nlookup: u64,
    ) -> anyhow::Result<()> {
        let nlookup = i64::try_from(nlookup)?;

        self.inode_table.clean_up_if(self.ino_from_fuse(ino), |n| {
            n.get_lookup_count().fetch_sub(nlookup, Ordering::SeqCst) <= nlookup
        });

        Ok(())
    }

    fn can_forget_multi(&self) -> bool {
        true
    }

    fn forget_multi(
        &self,
        req: FuseReq,
        forgets: &[crate::fuse_wrappers::bindings::fuse_forget_data],
    ) -> anyhow::Result<()> {
        for forget in forgets {
            self.forget(req, forget.ino, forget.nlookup)?;
        }
        Ok(())
    }

    fn can_mkdir(&self) -> bool {
        true
    }

    fn mkdir(
        &self,
        req: FuseReq,
        parent: crate::fuse_wrappers::bindings::fuse_ino_t,
        name: &std::ffi::CStr,
        mode: crate::fuse_wrappers::bindings::mode_t,
    ) -> anyhow::Result<crate::fuse_wrappers::bindings::fuse_entry_param> {
        let parent_node = self
            .inode_table
            .get(self.ino_from_fuse(parent))
            .ok_or(INodeNotFoundError::INodeNotInTable)?;
        let LiteINode::LiteDirINode(parent_dir) = &*parent_node else {
            return Err(Errno::NOTDIR)?;
        };
        let encoded_name = self.name_translator.encode_name(name.to_bytes())?;
        if self.name_translator.is_long_name(&encoded_name) {
            let encrypted_name = self.name_translator.encrypt_name(name.to_bytes())?;
            let table = parent_dir.ensure_writable_long_name_db()?;
            table.update_mapping(encoded_name.as_slice(), encrypted_name.as_slice())?;
        }
        rustix::fs::mkdirat(
            parent_dir.as_fd(),
            encoded_name.as_slice(),
            Mode::from_raw_mode(mode),
        )?;
        let dirfd = rustix::fs::openat(
            parent_dir.as_fd(),
            encoded_name,
            OFlags::RDONLY,
            Mode::empty(),
        )?;

        let mut stat = rustix::fs::fstat(dirfd.as_fd())?;
        let ino = INodeNumber(stat.st_ino);
        let generation = Generation(self.generation.load(Ordering::SeqCst));

        let child_node = self.inode_table.get_or_try_insert_with(ino, || {
            let header = LiteINodeHeader {
                ino,
                generation,
                lookup_count: AtomicI64::new(1),
                name_translator: self.name_translator.clone(),
            };
            Ok(LiteDirINode::new(header, dirfd).into())
        })?;
        child_node.readjust_stat(&mut stat)?;
        self.readjust_stat(&mut stat);
        let entry = fuse_entry_param {
            ino: stat.st_ino,
            generation: generation.0,
            attr: unsafe { std::mem::transmute(stat) },
            attr_timeout: self.attr_cache_duration.as_secs_f64(),
            entry_timeout: self.attr_cache_duration.as_secs_f64(),
        };
        Ok(entry)
    }

    fn can_unlink(&self) -> bool {
        true
    }

    fn unlink(
        &self,
        req: FuseReq,
        parent: crate::fuse_wrappers::bindings::fuse_ino_t,
        name: &std::ffi::CStr,
    ) -> anyhow::Result<()> {
        let parent_node = self
            .inode_table
            .get(self.ino_from_fuse(parent))
            .ok_or(INodeNotFoundError::INodeNotInTable)?;
        let LiteINode::LiteDirINode(parent_dir) = &*parent_node else {
            return Err(Errno::NOTDIR)?;
        };
        let encoded_name = self.name_translator.encode_name(name.to_bytes())?;
        rustix::fs::unlinkat(
            parent_dir.as_fd(),
            encoded_name.as_slice(),
            AtFlags::empty(),
        )?;
        if self.name_translator.is_long_name(&encoded_name) {
            let table = parent_dir.ensure_writable_long_name_db()?;
            table.remove_mapping(encoded_name.as_slice())?;
        }

        Ok(())
    }

    fn can_rmdir(&self) -> bool {
        true
    }

    fn rmdir(
        &self,
        req: FuseReq,
        parent: crate::fuse_wrappers::bindings::fuse_ino_t,
        name: &std::ffi::CStr,
    ) -> anyhow::Result<()> {
        let parent_node = self
            .inode_table
            .get(self.ino_from_fuse(parent))
            .ok_or(INodeNotFoundError::INodeNotInTable)?;
        let LiteINode::LiteDirINode(parent_dir) = &*parent_node else {
            return Err(Errno::NOTDIR)?;
        };
        let encoded_name = self.name_translator.encode_name(name.to_bytes())?;
        if let Err(err) = rustix::fs::unlinkat(
            parent_dir.as_fd(),
            encoded_name.as_slice(),
            AtFlags::REMOVEDIR,
        ) {
            tracing::trace!(
                "First attempt of rmdir ({:?}, {:?}) failed. Probably because of the long name db file. Full cause: {:?}",
                encoded_name,
                parent,
                err
            );
            rustix::fs::unlinkat(
                parent_dir.as_fd(),
                [
                    encoded_name.as_slice(),
                    b"/",
                    C_LONG_NAME_DB_FILENAME.to_bytes(),
                ]
                .concat()
                .as_slice(),
                AtFlags::empty(),
            )
            .context("deletion of long name db")?;
            rustix::fs::unlinkat(
                parent_dir.as_fd(),
                encoded_name.as_slice(),
                AtFlags::REMOVEDIR,
            )?;
        }

        if self.name_translator.is_long_name(&encoded_name) {
            let table = parent_dir.ensure_writable_long_name_db()?;
            table.remove_mapping(encoded_name.as_slice())?;
        }

        Ok(())
    }
}

fn timespec_to_systemtime(tv_sec: i64, tv_nsec: u32) -> SystemTime {
    if tv_sec >= 0 {
        SystemTime::UNIX_EPOCH + Duration::new(tv_sec as u64, tv_nsec)
    } else {
        SystemTime::UNIX_EPOCH - Duration::new(-tv_sec as u64, tv_nsec)
    }
}

pub mod testing {

    use std::path::Path;

    use protobuf::MessageField;

    use crate::{
        fuse_wrappers::{fuse_low_level_ops::TracedFuseOpsWrapper, fuse_main::run_fuse_main},
        lite::unix::create_vfs_for_fuse,
        protos::params::{
            DecryptedSecurefsParams, MountOptions,
            decrypted_securefs_params::{LiteFormatParams, SizeParams},
        },
    };

    pub fn simple_test_fuse_main() -> anyhow::Result<()> {
        let dec_params = DecryptedSecurefsParams {
            compat_version:5,
            size_params: MessageField::some(SizeParams {
                block_size: 333,
                iv_size: 12,
                max_padding_size: 17,
                special_fields: Default::default(),
            }),
            format_specific_params: Some(crate::protos::params::decrypted_securefs_params::Format_specific_params::LiteFormatParams(LiteFormatParams {
                name_key: vec![7u8;32],
                content_key: vec![8u8;32],
                xattr_key: vec![9u8;32],
                padding_key:vec![10u8;32],
                long_name_threshold: Some(12),
                long_name_suffix: ".LONG".into(),
                disable_legacy_additional_encryption_after_hashing_long_name: true,
                special_fields: Default::default(),
            })),
            special_fields: Default::default(),
        };
        let mount_options = MountOptions {
            mount_type_specific: Some(
                crate::protos::params::mount_options::Mount_type_specific::MountByKernelExt(
                    Default::default(),
                ),
            ),
            ..Default::default()
        };
        let mut root_tmp_dir = tempfile::TempDir::new()?;
        root_tmp_dir.disable_cleanup(true);
        tracing::info!("Root tmp dir: {:?}", root_tmp_dir.path());
        let mut vfs = Box::new(TracedFuseOpsWrapper::from(create_vfs_for_fuse(
            &dec_params,
            &mount_options,
            root_tmp_dir.path(),
        )?));
        std::fs::create_dir_all(Path::new("/tmp/nonprod_mount"))?;
        run_fuse_main(
            &[
                c"securefs",
                c"-o",
                c"default_permissions",
                c"/tmp/nonprod_mount",
            ],
            &mut vfs,
        )
    }
}

use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_int, c_uint, c_void},
};

use rustix::io::Errno;
use tracing::{Level, span};

use crate::{
    fuse_wrappers::bindings::{
        self, dev_t, fuse_add_direntry, fuse_conn_info, fuse_ctx, fuse_file_info, fuse_forget_data,
        fuse_ino_t, fuse_reply_attr, fuse_reply_bmap, fuse_reply_buf, fuse_reply_create,
        fuse_reply_entry, fuse_reply_err, fuse_reply_ioctl, fuse_reply_lock, fuse_reply_none,
        fuse_reply_open, fuse_reply_readlink, fuse_reply_statfs, fuse_reply_write,
        fuse_reply_xattr, fuse_req_ctx, fuse_req_t, fuse_req_userdata, mode_t, off_t, statvfs,
    },
    vfs::INodeNotFoundError,
};

#[derive(Debug, Copy, Clone)]
pub struct FuseReq {
    req: fuse_req_t,
}

impl FuseReq {
    pub fn get_context(&self) -> &fuse_ctx {
        unsafe { fuse_req_ctx(self.req).as_ref().unwrap() }
    }

    pub fn add_dir_entry(
        &mut self,
        buffer: &mut [u8],
        name: &CStr,
        st: &bindings::stat,
        off: off_t,
    ) -> usize {
        unsafe {
            fuse_add_direntry(
                self.req,
                buffer.as_ptr().cast_mut() as _,
                buffer.len(),
                name.as_ptr(),
                st,
                off,
            )
        }
    }
}

pub trait FuseLowLevelOps: Send + Sync {
    fn init(&mut self, conn: fuse_conn_info) -> fuse_conn_info;
    fn can_lookup(&self) -> bool {
        false
    }
    fn lookup(
        &self,
        req: FuseReq,
        parent: fuse_ino_t,
        name: &CStr,
    ) -> anyhow::Result<bindings::fuse_entry_param> {
        unimplemented!()
    }
    fn can_forget(&self) -> bool {
        false
    }
    fn forget(&self, req: FuseReq, ino: fuse_ino_t, nlookup: u64) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_getattr(&self) -> bool {
        false
    }
    fn getattr(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<(bindings::stat, f64)> {
        unimplemented!()
    }
    fn can_setattr(&self) -> bool {
        false
    }
    fn setattr(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        attr: &bindings::stat,
        to_set: i32,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<(bindings::stat, f64)> {
        unimplemented!()
    }
    fn can_readlink(&self) -> bool {
        false
    }
    fn readlink(&self, req: FuseReq, ino: fuse_ino_t) -> anyhow::Result<CString> {
        unimplemented!()
    }
    fn can_mknod(&self) -> bool {
        false
    }
    fn mknod(
        &self,
        req: FuseReq,
        parent: fuse_ino_t,
        name: &CStr,
        mode: mode_t,
        rdev: dev_t,
    ) -> anyhow::Result<bindings::fuse_entry_param> {
        unimplemented!()
    }
    fn can_mkdir(&self) -> bool {
        false
    }
    fn mkdir(
        &self,
        req: FuseReq,
        parent: fuse_ino_t,
        name: &CStr,
        mode: mode_t,
    ) -> anyhow::Result<bindings::fuse_entry_param> {
        unimplemented!()
    }
    fn can_unlink(&self) -> bool {
        false
    }
    fn unlink(&self, req: FuseReq, parent: fuse_ino_t, name: &CStr) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_rmdir(&self) -> bool {
        false
    }
    fn rmdir(&self, req: FuseReq, parent: fuse_ino_t, name: &CStr) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_symlink(&self) -> bool {
        false
    }
    fn symlink(
        &self,
        req: FuseReq,
        link: &CStr,
        parent: fuse_ino_t,
        name: &CStr,
    ) -> anyhow::Result<bindings::fuse_entry_param> {
        unimplemented!()
    }
    fn can_rename(&self) -> bool {
        false
    }
    fn rename(
        &self,
        req: FuseReq,
        parent: fuse_ino_t,
        name: &CStr,
        newparent: fuse_ino_t,
        newname: &CStr,
        flags: u32,
    ) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_link(&self) -> bool {
        false
    }
    fn link(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        newparent: fuse_ino_t,
        newname: &CStr,
    ) -> anyhow::Result<bindings::fuse_entry_param> {
        unimplemented!()
    }
    fn can_open(&self) -> bool {
        false
    }
    fn open(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<bindings::fuse_file_info> {
        unimplemented!()
    }
    fn can_read(&self) -> bool {
        false
    }
    fn read(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        size: usize,
        off: off_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<Vec<u8>> {
        unimplemented!()
    }
    fn can_write(&self) -> bool {
        false
    }
    fn write(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        buf: &[u8],
        off: off_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<usize> {
        unimplemented!()
    }
    fn can_flush(&self) -> bool {
        false
    }
    fn flush(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_release(&self) -> bool {
        false
    }
    fn release(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_fsync(&self) -> bool {
        false
    }
    fn fsync(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        datasync: i32,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_opendir(&self) -> bool {
        false
    }
    fn opendir(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<bindings::fuse_file_info> {
        unimplemented!()
    }
    fn can_readdir(&self) -> bool {
        false
    }
    fn readdir(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        size: usize,
        off: off_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<Vec<u8>> {
        unimplemented!()
    }
    fn can_releasedir(&self) -> bool {
        false
    }
    fn releasedir(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_fsyncdir(&self) -> bool {
        false
    }
    fn fsyncdir(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        datasync: i32,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_statfs(&self) -> bool {
        false
    }
    fn statfs(&self, req: FuseReq, ino: fuse_ino_t) -> anyhow::Result<statvfs> {
        unimplemented!()
    }
    fn can_setxattr(&self) -> bool {
        false
    }
    fn setxattr(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        name: &CStr,
        value: &[u8],
        flags: i32,
    ) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_getxattr(&self) -> bool {
        false
    }
    fn getxattr(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        name: &CStr,
        size: usize,
    ) -> anyhow::Result<Vec<u8>> {
        unimplemented!()
    }
    fn can_listxattr(&self) -> bool {
        false
    }
    fn listxattr(&self, req: FuseReq, ino: fuse_ino_t, size: usize) -> anyhow::Result<Vec<u8>> {
        unimplemented!()
    }
    fn can_removexattr(&self) -> bool {
        false
    }
    fn removexattr(&self, req: FuseReq, ino: fuse_ino_t, name: &CStr) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_access(&self) -> bool {
        false
    }
    fn access(&self, ino: fuse_ino_t, mask: i32) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_create(&self) -> bool {
        false
    }
    fn create(
        &self,
        req: FuseReq,
        parent: fuse_ino_t,
        name: &CStr,
        mode: mode_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<(bindings::fuse_entry_param, bindings::fuse_file_info)> {
        unimplemented!()
    }
    fn can_getlk(&self) -> bool {
        false
    }
    fn getlk(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
        lock: &bindings::flock,
    ) -> anyhow::Result<bindings::flock> {
        unimplemented!()
    }
    fn can_setlk(&self) -> bool {
        false
    }
    fn setlk(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
        lock: &bindings::flock,
        sleep: i32,
    ) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_bmap(&self) -> bool {
        false
    }
    fn bmap(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        blocksize: usize,
        idx: u64,
    ) -> anyhow::Result<u64> {
        unimplemented!()
    }
    fn can_ioctl(&self) -> bool {
        false
    }
    fn ioctl(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        cmd: u32,
        arg: *mut c_void, // This is an opaque pointer that the implementation may write to
        fi: Option<&bindings::fuse_file_info>,
        flags: u32,
        in_buf: &[u8],
        out_bufsz: usize,
    ) -> anyhow::Result<(i32, Vec<u8>)> {
        unimplemented!()
    }
    fn can_poll(&self) -> bool {
        false
    }
    fn poll(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
        ph: &mut bindings::fuse_pollhandle,
    ) -> anyhow::Result<u32> {
        unimplemented!()
    }
    fn can_write_buf(&self) -> bool {
        false
    }
    fn write_buf(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        bufv: &mut bindings::fuse_bufvec,
        off: off_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<usize> {
        unimplemented!()
    }
    fn can_forget_multi(&self) -> bool {
        false
    }
    fn forget_multi(&self, req: FuseReq, forgets: &[fuse_forget_data]) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_flock(&self) -> bool {
        false
    }
    fn flock(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
        op: i32,
    ) -> anyhow::Result<()> {
        unimplemented!()
    }
}

pub struct TracedFuseOpsWrapper<T: FuseLowLevelOps> {
    ops: T,
}

impl<T: FuseLowLevelOps> From<T> for TracedFuseOpsWrapper<T> {
    fn from(value: T) -> Self {
        Self { ops: value }
    }
}

impl<T: FuseLowLevelOps> FuseLowLevelOps for TracedFuseOpsWrapper<T> {
    fn init(&mut self, conn: fuse_conn_info) -> fuse_conn_info {
        let _span = span!(Level::ERROR, "init").entered();
        let ret = self.ops.init(conn);
        tracing::debug!(?conn, ?ret);
        ret
    }

    fn can_lookup(&self) -> bool {
        self.ops.can_lookup()
    }

    fn lookup(
        &self,
        req: FuseReq,
        parent: fuse_ino_t,
        name: &CStr,
    ) -> anyhow::Result<bindings::fuse_entry_param> {
        let _span = span!(Level::ERROR, "lookup").entered();
        match self.ops.lookup(req, parent, name) {
            Ok(ret) => {
                tracing::debug!(?req, parent, ?name, ?ret);
                Ok(ret)
            }
            Err(err) => {
                if let Some(e) = err.downcast_ref::<Errno>()
                    && *e == Errno::NOENT
                {
                    tracing::debug!(?req, parent, ?name, err = "inode not found");
                } else {
                    tracing::warn!(?req, parent, ?name, ?err);
                }
                Err(err)
            }
        }
    }

    fn can_forget(&self) -> bool {
        self.ops.can_forget()
    }

    fn forget(&self, req: FuseReq, ino: fuse_ino_t, nlookup: u64) -> anyhow::Result<()> {
        let _span = span!(Level::ERROR, "forget").entered();
        match self.ops.forget(req, ino, nlookup) {
            Ok(()) => {
                tracing::debug!(?req, ino, nlookup);
                Ok(())
            }
            Err(err) => {
                tracing::warn!(?req, ino, nlookup, ?err);
                Err(err)
            }
        }
    }

    fn can_getattr(&self) -> bool {
        self.ops.can_getattr()
    }

    fn getattr(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<(bindings::stat, f64)> {
        let _span = span!(Level::ERROR, "getattr").entered();
        match self.ops.getattr(req, ino, fi) {
            Ok(ret) => {
                tracing::debug!(?req, ino, ?fi, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?req, ino, ?fi, ?err);
                Err(err)
            }
        }
    }

    fn can_setattr(&self) -> bool {
        self.ops.can_setattr()
    }

    fn setattr(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        attr: &bindings::stat,
        to_set: i32,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<(bindings::stat, f64)> {
        let _span = span!(Level::ERROR, "setattr").entered();
        match self.ops.setattr(req, ino, attr, to_set, fi) {
            Ok(ret) => {
                tracing::debug!(?req, ino, ?attr, to_set, ?fi, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?req, ino, ?attr, to_set, ?fi, ?err);
                Err(err)
            }
        }
    }

    fn can_readlink(&self) -> bool {
        self.ops.can_readlink()
    }

    fn readlink(&self, req: FuseReq, ino: fuse_ino_t) -> anyhow::Result<CString> {
        let _span = span!(Level::ERROR, "readlink").entered();
        match self.ops.readlink(req, ino) {
            Ok(ret) => {
                tracing::debug!(?req, ino, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?req, ino, ?err);
                Err(err)
            }
        }
    }

    fn can_mknod(&self) -> bool {
        self.ops.can_mknod()
    }

    fn mknod(
        &self,
        req: FuseReq,
        parent: fuse_ino_t,
        name: &CStr,
        mode: mode_t,
        rdev: dev_t,
    ) -> anyhow::Result<bindings::fuse_entry_param> {
        let _span = span!(Level::ERROR, "mknod").entered();
        match self.ops.mknod(req, parent, name, mode, rdev) {
            Ok(ret) => {
                tracing::debug!(?req, parent, ?name, mode, rdev, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?req, parent, ?name, mode, rdev, ?err);
                Err(err)
            }
        }
    }

    fn can_mkdir(&self) -> bool {
        self.ops.can_mkdir()
    }

    fn mkdir(
        &self,
        req: FuseReq,
        parent: fuse_ino_t,
        name: &CStr,
        mode: mode_t,
    ) -> anyhow::Result<bindings::fuse_entry_param> {
        let _span = span!(Level::ERROR, "mkdir").entered();
        match self.ops.mkdir(req, parent, name, mode) {
            Ok(ret) => {
                tracing::debug!(?req, parent, ?name, mode, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?req, parent, ?name, mode, ?err);
                Err(err)
            }
        }
    }

    fn can_unlink(&self) -> bool {
        self.ops.can_unlink()
    }

    fn unlink(&self, req: FuseReq, parent: fuse_ino_t, name: &CStr) -> anyhow::Result<()> {
        let _span = span!(Level::ERROR, "unlink").entered();
        match self.ops.unlink(req, parent, name) {
            Ok(()) => {
                tracing::debug!(?req, parent, ?name);
                Ok(())
            }
            Err(err) => {
                tracing::warn!(?req, parent, ?name, ?err);
                Err(err)
            }
        }
    }

    fn can_rmdir(&self) -> bool {
        self.ops.can_rmdir()
    }

    fn rmdir(&self, req: FuseReq, parent: fuse_ino_t, name: &CStr) -> anyhow::Result<()> {
        let _span = span!(Level::ERROR, "rmdir").entered();
        match self.ops.rmdir(req, parent, name) {
            Ok(()) => {
                tracing::debug!(?req, parent, ?name);
                Ok(())
            }
            Err(err) => {
                tracing::warn!(?req, parent, ?name, ?err);
                Err(err)
            }
        }
    }

    fn can_symlink(&self) -> bool {
        self.ops.can_symlink()
    }

    fn symlink(
        &self,
        req: FuseReq,
        link: &CStr,
        parent: fuse_ino_t,
        name: &CStr,
    ) -> anyhow::Result<bindings::fuse_entry_param> {
        let _span = span!(Level::ERROR, "symlink").entered();
        match self.ops.symlink(req, link, parent, name) {
            Ok(ret) => {
                tracing::debug!(?req, ?link, parent, ?name, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?req, ?link, parent, ?name, ?err);
                Err(err)
            }
        }
    }

    fn can_rename(&self) -> bool {
        self.ops.can_rename()
    }

    fn rename(
        &self,
        req: FuseReq,
        parent: fuse_ino_t,
        name: &CStr,
        newparent: fuse_ino_t,
        newname: &CStr,
        flags: u32,
    ) -> anyhow::Result<()> {
        let _span = span!(Level::ERROR, "rename").entered();
        match self
            .ops
            .rename(req, parent, name, newparent, newname, flags)
        {
            Ok(()) => {
                tracing::debug!(?req, parent, ?name, newparent, ?newname, flags);
                Ok(())
            }
            Err(err) => {
                tracing::warn!(?req, parent, ?name, newparent, ?newname, flags, ?err);
                Err(err)
            }
        }
    }

    fn can_link(&self) -> bool {
        self.ops.can_link()
    }

    fn link(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        newparent: fuse_ino_t,
        newname: &CStr,
    ) -> anyhow::Result<bindings::fuse_entry_param> {
        let _span = span!(Level::ERROR, "link").entered();
        match self.ops.link(req, ino, newparent, newname) {
            Ok(ret) => {
                tracing::debug!(?req, ino, newparent, ?newname, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?req, ino, newparent, ?newname, ?err);
                Err(err)
            }
        }
    }

    fn can_open(&self) -> bool {
        self.ops.can_open()
    }

    fn open(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<bindings::fuse_file_info> {
        let _span = span!(Level::ERROR, "open").entered();
        match self.ops.open(req, ino, fi) {
            Ok(ret) => {
                tracing::debug!(?req, ino, ?fi, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?req, ino, ?fi, ?err);
                Err(err)
            }
        }
    }

    fn can_read(&self) -> bool {
        self.ops.can_read()
    }

    fn read(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        size: usize,
        off: off_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<Vec<u8>> {
        let _span = span!(Level::ERROR, "read").entered();
        match self.ops.read(req, ino, size, off, fi) {
            Ok(ret) => {
                tracing::debug!(?req, ino, size, off, ?fi, ret.len = ret.len());
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?req, ino, size, off, ?fi, ?err);
                Err(err)
            }
        }
    }

    fn can_write(&self) -> bool {
        self.ops.can_write()
    }

    fn write(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        buf: &[u8],
        off: off_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<usize> {
        let _span = span!(Level::ERROR, "write").entered();
        match self.ops.write(req, ino, buf, off, fi) {
            Ok(ret) => {
                tracing::debug!(?req, ino, buf.len = buf.len(), off, ?fi, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?req, ino, buf.len = buf.len(), off, ?fi, ?err);
                Err(err)
            }
        }
    }

    fn can_flush(&self) -> bool {
        self.ops.can_flush()
    }

    fn flush(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<()> {
        let _span = span!(Level::ERROR, "flush").entered();
        match self.ops.flush(req, ino, fi) {
            Ok(()) => {
                tracing::debug!(?req, ino, ?fi);
                Ok(())
            }
            Err(err) => {
                tracing::warn!(?req, ino, ?fi, ?err);
                Err(err)
            }
        }
    }

    fn can_release(&self) -> bool {
        self.ops.can_release()
    }

    fn release(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<()> {
        let _span = span!(Level::ERROR, "release").entered();
        match self.ops.release(req, ino, fi) {
            Ok(()) => {
                tracing::debug!(?req, ino, ?fi);
                Ok(())
            }
            Err(err) => {
                tracing::warn!(?req, ino, ?fi, ?err);
                Err(err)
            }
        }
    }

    fn can_fsync(&self) -> bool {
        self.ops.can_fsync()
    }

    fn fsync(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        datasync: i32,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<()> {
        let _span = span!(Level::ERROR, "fsync").entered();
        match self.ops.fsync(req, ino, datasync, fi) {
            Ok(()) => {
                tracing::debug!(?req, ino, datasync, ?fi);
                Ok(())
            }
            Err(err) => {
                tracing::warn!(?req, ino, datasync, ?fi, ?err);
                Err(err)
            }
        }
    }

    fn can_opendir(&self) -> bool {
        self.ops.can_opendir()
    }

    fn opendir(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<bindings::fuse_file_info> {
        let _span = span!(Level::ERROR, "opendir").entered();
        match self.ops.opendir(req, ino, fi) {
            Ok(ret) => {
                tracing::debug!(?req, ino, ?fi, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?req, ino, ?fi, ?err);
                Err(err)
            }
        }
    }

    fn can_readdir(&self) -> bool {
        self.ops.can_readdir()
    }

    fn readdir(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        size: usize,
        off: off_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<Vec<u8>> {
        let _span = span!(Level::ERROR, "readdir").entered();
        match self.ops.readdir(req, ino, size, off, fi) {
            Ok(ret) => {
                tracing::debug!(?req, ino, size, off, ?fi, ret.len = ret.len());
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?req, ino, size, off, ?fi, ?err);
                Err(err)
            }
        }
    }

    fn can_releasedir(&self) -> bool {
        self.ops.can_releasedir()
    }

    fn releasedir(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<()> {
        let _span = span!(Level::ERROR, "releasedir").entered();
        match self.ops.releasedir(req, ino, fi) {
            Ok(()) => {
                tracing::debug!(?req, ino, ?fi);
                Ok(())
            }
            Err(err) => {
                tracing::warn!(?req, ino, ?fi, ?err);
                Err(err)
            }
        }
    }

    fn can_fsyncdir(&self) -> bool {
        self.ops.can_fsyncdir()
    }

    fn fsyncdir(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        datasync: i32,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<()> {
        let _span = span!(Level::ERROR, "fsyncdir").entered();
        match self.ops.fsyncdir(req, ino, datasync, fi) {
            Ok(()) => {
                tracing::debug!(?req, ino, datasync, ?fi);
                Ok(())
            }
            Err(err) => {
                tracing::warn!(?req, ino, datasync, ?fi, ?err);
                Err(err)
            }
        }
    }

    fn can_statfs(&self) -> bool {
        self.ops.can_statfs()
    }

    fn statfs(&self, req: FuseReq, ino: fuse_ino_t) -> anyhow::Result<statvfs> {
        let _span = span!(Level::ERROR, "statfs").entered();
        match self.ops.statfs(req, ino) {
            Ok(ret) => {
                tracing::debug!(?req, ino, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?req, ino, ?err);
                Err(err)
            }
        }
    }

    fn can_setxattr(&self) -> bool {
        self.ops.can_setxattr()
    }

    fn setxattr(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        name: &CStr,
        value: &[u8],
        flags: i32,
    ) -> anyhow::Result<()> {
        let _span = span!(Level::ERROR, "setxattr").entered();
        match self.ops.setxattr(req, ino, name, value, flags) {
            Ok(()) => {
                tracing::debug!(?req, ino, ?name, value.len = value.len(), flags);
                Ok(())
            }
            Err(err) => {
                tracing::warn!(?req, ino, ?name, value.len = value.len(), flags, ?err);
                Err(err)
            }
        }
    }

    fn can_getxattr(&self) -> bool {
        self.ops.can_getxattr()
    }

    fn getxattr(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        name: &CStr,
        size: usize,
    ) -> anyhow::Result<Vec<u8>> {
        let _span = span!(Level::ERROR, "getxattr").entered();
        match self.ops.getxattr(req, ino, name, size) {
            Ok(ret) => {
                tracing::debug!(?req, ino, ?name, size, ret.len = ret.len());
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?req, ino, ?name, size, ?err);
                Err(err)
            }
        }
    }

    fn can_listxattr(&self) -> bool {
        self.ops.can_listxattr()
    }

    fn listxattr(&self, req: FuseReq, ino: fuse_ino_t, size: usize) -> anyhow::Result<Vec<u8>> {
        let _span = span!(Level::ERROR, "listxattr").entered();
        match self.ops.listxattr(req, ino, size) {
            Ok(ret) => {
                tracing::debug!(?req, ino, size, ret.len = ret.len());
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?req, ino, size, ?err);
                Err(err)
            }
        }
    }

    fn can_removexattr(&self) -> bool {
        self.ops.can_removexattr()
    }

    fn removexattr(&self, req: FuseReq, ino: fuse_ino_t, name: &CStr) -> anyhow::Result<()> {
        let _span = span!(Level::ERROR, "removexattr").entered();
        match self.ops.removexattr(req, ino, name) {
            Ok(()) => {
                tracing::debug!(?req, ino, ?name);
                Ok(())
            }
            Err(err) => {
                tracing::warn!(?req, ino, ?name, ?err);
                Err(err)
            }
        }
    }

    fn can_access(&self) -> bool {
        self.ops.can_access()
    }

    fn access(&self, ino: fuse_ino_t, mask: i32) -> anyhow::Result<()> {
        let _span = span!(Level::ERROR, "access").entered();
        match self.ops.access(ino, mask) {
            Ok(()) => {
                tracing::debug!(ino, mask);
                Ok(())
            }
            Err(err) => {
                tracing::warn!(ino, mask, ?err);
                Err(err)
            }
        }
    }

    fn can_create(&self) -> bool {
        self.ops.can_create()
    }

    fn create(
        &self,
        req: FuseReq,
        parent: fuse_ino_t,
        name: &CStr,
        mode: mode_t,
        fi: Option<&bindings::fuse_file_info>,
    ) -> anyhow::Result<(bindings::fuse_entry_param, bindings::fuse_file_info)> {
        let _span = span!(Level::ERROR, "create").entered();
        match self.ops.create(req, parent, name, mode, fi) {
            Ok(ret) => {
                tracing::debug!(?req, parent, ?name, mode, ?fi, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?req, parent, ?name, mode, ?fi, ?err);
                Err(err)
            }
        }
    }

    fn can_getlk(&self) -> bool {
        self.ops.can_getlk()
    }

    fn getlk(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
        lock: &bindings::flock,
    ) -> anyhow::Result<bindings::flock> {
        let _span = span!(Level::ERROR, "getlk").entered();
        match self.ops.getlk(req, ino, fi, lock) {
            Ok(ret) => {
                tracing::debug!(?req, ino, ?fi, ?lock, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?req, ino, ?fi, ?lock, ?err);
                Err(err)
            }
        }
    }

    fn can_setlk(&self) -> bool {
        self.ops.can_setlk()
    }

    fn setlk(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
        lock: &bindings::flock,
        sleep: i32,
    ) -> anyhow::Result<()> {
        let _span = span!(Level::ERROR, "setlk").entered();
        match self.ops.setlk(req, ino, fi, lock, sleep) {
            Ok(()) => {
                tracing::debug!(?req, ino, ?fi, ?lock, sleep);
                Ok(())
            }
            Err(err) => {
                tracing::warn!(?req, ino, ?fi, ?lock, sleep, ?err);
                Err(err)
            }
        }
    }

    fn can_bmap(&self) -> bool {
        self.ops.can_bmap()
    }

    fn bmap(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        blocksize: usize,
        idx: u64,
    ) -> anyhow::Result<u64> {
        let _span = span!(Level::ERROR, "bmap").entered();
        match self.ops.bmap(req, ino, blocksize, idx) {
            Ok(ret) => {
                tracing::debug!(?req, ino, blocksize, idx, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?req, ino, blocksize, idx, ?err);
                Err(err)
            }
        }
    }

    fn can_ioctl(&self) -> bool {
        self.ops.can_ioctl()
    }

    fn ioctl(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        cmd: u32,
        arg: *mut c_void,
        fi: Option<&bindings::fuse_file_info>,
        flags: u32,
        in_buf: &[u8],
        out_bufsz: usize,
    ) -> anyhow::Result<(i32, Vec<u8>)> {
        let _span = span!(Level::ERROR, "ioctl").entered();
        match self
            .ops
            .ioctl(req, ino, cmd, arg, fi, flags, in_buf, out_bufsz)
        {
            Ok(ret) => {
                tracing::debug!(
                    ?req,
                    ino,
                    cmd,
                    ?arg,
                    ?fi,
                    flags,
                    in_buf.len = in_buf.len(),
                    out_bufsz,
                    ?ret
                );
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(
                    ?req,
                    ino,
                    cmd,
                    ?arg,
                    ?fi,
                    flags,
                    in_buf.len = in_buf.len(),
                    out_bufsz,
                    ?err
                );
                Err(err)
            }
        }
    }

    fn can_poll(&self) -> bool {
        self.ops.can_poll()
    }

    fn poll(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
        ph: &mut bindings::fuse_pollhandle,
    ) -> anyhow::Result<u32> {
        let _span = span!(Level::ERROR, "poll").entered();
        match self.ops.poll(req, ino, fi, ph) {
            Ok(ret) => {
                tracing::debug!(?req, ino, ?fi, ?ph, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?req, ino, ?fi, ?ph, ?err);
                Err(err)
            }
        }
    }

    fn can_forget_multi(&self) -> bool {
        self.ops.can_forget_multi()
    }

    fn forget_multi(&self, req: FuseReq, forgets: &[fuse_forget_data]) -> anyhow::Result<()> {
        let _span = span!(Level::ERROR, "forget_multi").entered();
        match self.ops.forget_multi(req, forgets) {
            Ok(()) => {
                tracing::debug!(?req, ?forgets);
                Ok(())
            }
            Err(err) => {
                tracing::warn!(?req, ?forgets, ?err);
                Err(err)
            }
        }
    }

    fn can_flock(&self) -> bool {
        self.ops.can_flock()
    }

    fn flock(
        &self,
        req: FuseReq,
        ino: fuse_ino_t,
        fi: Option<&bindings::fuse_file_info>,
        op: i32,
    ) -> anyhow::Result<()> {
        let _span = span!(Level::ERROR, "flock").entered();
        match self.ops.flock(req, ino, fi, op) {
            Ok(()) => {
                tracing::debug!(?req, ino, ?fi, op);
                Ok(())
            }
            Err(err) => {
                tracing::warn!(?req, ino, ?fi, op, ?err);
                Err(err)
            }
        }
    }
}

fn get_ops<T: FuseLowLevelOps>(req: &fuse_req_t) -> &T {
    unsafe { &*{ fuse_req_userdata(*req) as *const T } }
}

extern "C" fn rs_init<T: FuseLowLevelOps>(
    userdata: *mut ::std::os::raw::c_void,
    conn: *mut fuse_conn_info,
) {
    unsafe {
        let userdata = userdata as *mut T;
        let new_conn = (*userdata).init(*conn);
        *conn = new_conn;
    }
}

extern "C" fn rs_lookup<T: FuseLowLevelOps>(
    req: fuse_req_t,
    parent: fuse_ino_t,
    name: *const ::std::os::raw::c_char,
) {
    let name = unsafe { CStr::from_ptr(name) };
    match get_ops::<T>(&req).lookup(FuseReq { req }, parent, name) {
        Ok(entry) => unsafe {
            fuse_reply_entry(req, &entry);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_forget<T: FuseLowLevelOps>(req: fuse_req_t, ino: fuse_ino_t, nlookup: u64) {
    match get_ops::<T>(&req).forget(FuseReq { req }, ino, nlookup) {
        Ok(_) => unsafe {
            fuse_reply_none(req);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_getattr<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    fi: *mut fuse_file_info,
) {
    match get_ops::<T>(&req).getattr(FuseReq { req }, ino, unsafe { fi.as_ref() }) {
        Ok((stat, timeout)) => unsafe {
            fuse_reply_attr(req, &stat, timeout);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_setattr<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    attr: *mut bindings::stat,
    to_set: c_int,
    fi: *mut fuse_file_info,
) {
    match get_ops::<T>(&req).setattr(FuseReq { req }, ino, unsafe { &*attr }, to_set, unsafe {
        fi.as_ref()
    }) {
        Ok((stat, timeout)) => unsafe {
            fuse_reply_attr(req, &stat, timeout);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_readlink<T: FuseLowLevelOps>(req: fuse_req_t, ino: fuse_ino_t) {
    match get_ops::<T>(&req).readlink(FuseReq { req }, ino) {
        Ok(link) => unsafe {
            fuse_reply_readlink(req, link.as_ptr());
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_mknod<T: FuseLowLevelOps>(
    req: fuse_req_t,
    parent: fuse_ino_t,
    name: *const c_char,
    mode: mode_t,
    rdev: dev_t,
) {
    let name = unsafe { CStr::from_ptr(name) };
    match get_ops::<T>(&req).mknod(FuseReq { req }, parent, name, mode, rdev) {
        Ok(entry) => unsafe {
            fuse_reply_entry(req, &entry);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_mkdir<T: FuseLowLevelOps>(
    req: fuse_req_t,
    parent: fuse_ino_t,
    name: *const c_char,
    mode: mode_t,
) {
    let name = unsafe { CStr::from_ptr(name) };
    match get_ops::<T>(&req).mkdir(FuseReq { req }, parent, name, mode) {
        Ok(entry) => unsafe {
            fuse_reply_entry(req, &entry);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_unlink<T: FuseLowLevelOps>(
    req: fuse_req_t,
    parent: fuse_ino_t,
    name: *const c_char,
) {
    let name = unsafe { CStr::from_ptr(name) };
    match get_ops::<T>(&req).unlink(FuseReq { req }, parent, name) {
        Ok(()) => unsafe {
            fuse_reply_err(req, 0);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_rmdir<T: FuseLowLevelOps>(
    req: fuse_req_t,
    parent: fuse_ino_t,
    name: *const c_char,
) {
    let name = unsafe { CStr::from_ptr(name) };
    match get_ops::<T>(&req).rmdir(FuseReq { req }, parent, name) {
        Ok(()) => unsafe {
            fuse_reply_err(req, 0);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_symlink<T: FuseLowLevelOps>(
    req: fuse_req_t,
    link: *const c_char,
    parent: fuse_ino_t,
    name: *const c_char,
) {
    let link = unsafe { CStr::from_ptr(link) };
    let name = unsafe { CStr::from_ptr(name) };
    match get_ops::<T>(&req).symlink(FuseReq { req }, link, parent, name) {
        Ok(entry) => unsafe {
            fuse_reply_entry(req, &entry);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_rename<T: FuseLowLevelOps>(
    req: fuse_req_t,
    parent: fuse_ino_t,
    name: *const c_char,
    newparent: fuse_ino_t,
    newname: *const c_char,
    flags: u32,
) {
    let name = unsafe { CStr::from_ptr(name) };
    let newname = unsafe { CStr::from_ptr(newname) };
    match get_ops::<T>(&req).rename(FuseReq { req }, parent, name, newparent, newname, flags) {
        Ok(()) => unsafe {
            fuse_reply_err(req, 0);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_link<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    newparent: fuse_ino_t,
    newname: *const c_char,
) {
    let newname = unsafe { CStr::from_ptr(newname) };
    match get_ops::<T>(&req).link(FuseReq { req }, ino, newparent, newname) {
        Ok(entry) => unsafe {
            fuse_reply_entry(req, &entry);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_open<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    fi: *mut fuse_file_info,
) {
    match get_ops::<T>(&req).open(FuseReq { req }, ino, unsafe { fi.as_ref() }) {
        Ok(new_fi) => unsafe {
            fuse_reply_open(req, &new_fi);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_read<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    size: usize,
    off: off_t,
    fi: *mut fuse_file_info,
) {
    match get_ops::<T>(&req).read(FuseReq { req }, ino, size, off, unsafe { fi.as_ref() }) {
        Ok(data) => unsafe {
            fuse_reply_buf(req, data.as_ptr() as *const c_char, data.len());
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_write<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    buf: *const c_char,
    size: usize,
    off: off_t,
    fi: *mut fuse_file_info,
) {
    let slice = unsafe { std::slice::from_raw_parts(buf as *const u8, size) };
    match get_ops::<T>(&req).write(FuseReq { req }, ino, slice, off, unsafe { fi.as_ref() }) {
        Ok(written) => unsafe {
            fuse_reply_write(req, written);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_flush<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    fi: *mut fuse_file_info,
) {
    match get_ops::<T>(&req).flush(FuseReq { req }, ino, unsafe { fi.as_ref() }) {
        Ok(()) => unsafe {
            fuse_reply_err(req, 0);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_release<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    fi: *mut fuse_file_info,
) {
    match get_ops::<T>(&req).release(FuseReq { req }, ino, unsafe { fi.as_ref() }) {
        Ok(()) => unsafe {
            fuse_reply_err(req, 0);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_fsync<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    datasync: c_int,
    fi: *mut fuse_file_info,
) {
    match get_ops::<T>(&req).fsync(FuseReq { req }, ino, datasync, unsafe { fi.as_ref() }) {
        Ok(()) => unsafe {
            fuse_reply_err(req, 0);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_opendir<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    fi: *mut fuse_file_info,
) {
    match get_ops::<T>(&req).opendir(FuseReq { req }, ino, unsafe { fi.as_ref() }) {
        Ok(fi) => unsafe {
            fuse_reply_open(req, &fi);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_readdir<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    size: usize,
    off: off_t,
    fi: *mut fuse_file_info,
) {
    match get_ops::<T>(&req).readdir(FuseReq { req }, ino, size, off, unsafe { fi.as_ref() }) {
        Ok(data) => unsafe {
            fuse_reply_buf(req, data.as_ptr() as *const c_char, data.len());
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_releasedir<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    fi: *mut fuse_file_info,
) {
    match get_ops::<T>(&req).releasedir(FuseReq { req }, ino, unsafe { fi.as_ref() }) {
        Ok(()) => unsafe {
            fuse_reply_err(req, 0);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_fsyncdir<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    datasync: c_int,
    fi: *mut fuse_file_info,
) {
    match get_ops::<T>(&req).fsyncdir(FuseReq { req }, ino, datasync, unsafe { fi.as_ref() }) {
        Ok(()) => unsafe {
            fuse_reply_err(req, 0);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_statfs<T: FuseLowLevelOps>(req: fuse_req_t, ino: fuse_ino_t) {
    match get_ops::<T>(&req).statfs(FuseReq { req }, ino) {
        Ok(stbuf) => unsafe {
            fuse_reply_statfs(req, &stbuf);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_setxattr<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    name: *const c_char,
    value: *const c_char,
    size: usize,
    flags: c_int,
) {
    let name = unsafe { CStr::from_ptr(name) };
    let value = unsafe { std::slice::from_raw_parts(value as *const u8, size) };
    match get_ops::<T>(&req).setxattr(FuseReq { req }, ino, name, value, flags) {
        Ok(()) => unsafe {
            fuse_reply_err(req, 0);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_getxattr<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    name: *const c_char,
    size: usize,
) {
    let name = unsafe { CStr::from_ptr(name) };
    match get_ops::<T>(&req).getxattr(FuseReq { req }, ino, name, size) {
        Ok(data) => {
            if size == 0 {
                unsafe { fuse_reply_xattr(req, data.len()) };
            } else {
                unsafe { fuse_reply_buf(req, data.as_ptr() as *const c_char, data.len()) };
            }
        }
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_listxattr<T: FuseLowLevelOps>(req: fuse_req_t, ino: fuse_ino_t, size: usize) {
    match get_ops::<T>(&req).listxattr(FuseReq { req }, ino, size) {
        Ok(data) => {
            if size == 0 {
                unsafe { fuse_reply_xattr(req, data.len()) };
            } else {
                unsafe { fuse_reply_buf(req, data.as_ptr() as *const c_char, data.len()) };
            }
        }
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_removexattr<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    name: *const c_char,
) {
    let name = unsafe { CStr::from_ptr(name) };
    match get_ops::<T>(&req).removexattr(FuseReq { req }, ino, name) {
        Ok(()) => unsafe {
            fuse_reply_err(req, 0);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_access<T: FuseLowLevelOps>(req: fuse_req_t, ino: fuse_ino_t, mask: c_int) {
    match get_ops::<T>(&req).access(ino, mask) {
        Ok(()) => unsafe {
            fuse_reply_err(req, 0);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_create<T: FuseLowLevelOps>(
    req: fuse_req_t,
    parent: fuse_ino_t,
    name: *const c_char,
    mode: mode_t,
    fi: *mut fuse_file_info,
) {
    let name = unsafe { CStr::from_ptr(name) };
    match get_ops::<T>(&req).create(FuseReq { req }, parent, name, mode, unsafe { fi.as_ref() }) {
        Ok((entry, fi)) => unsafe {
            fuse_reply_create(req, &entry, &fi);
        },
        Err(e) => unsafe {
            log::warn!("create({req:?}, {parent:?}, {name:?}, {mode:?}, {fi:?}) failed with {e:?}");
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_getlk<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    fi: *mut fuse_file_info,
    lock: *mut bindings::flock,
) {
    match get_ops::<T>(&req).getlk(FuseReq { req }, ino, unsafe { fi.as_ref() }, unsafe {
        &*lock
    }) {
        Ok(lock) => unsafe {
            fuse_reply_lock(req, &lock);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_setlk<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    fi: *mut fuse_file_info,
    lock: *mut bindings::flock,
    sleep: c_int,
) {
    match get_ops::<T>(&req).setlk(
        FuseReq { req },
        ino,
        unsafe { fi.as_ref() },
        unsafe { &*lock },
        sleep,
    ) {
        Ok(()) => unsafe {
            fuse_reply_err(req, 0);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_bmap<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    blocksize: usize,
    idx: u64,
) {
    match get_ops::<T>(&req).bmap(FuseReq { req }, ino, blocksize, idx) {
        Ok(idx) => unsafe {
            fuse_reply_bmap(req, idx);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_ioctl<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    cmd: c_uint,
    arg: *mut c_void,
    fi: *mut fuse_file_info,
    flags: c_uint,
    in_buf: *const c_void,
    in_bufsz: usize,
    out_bufsz: usize,
) {
    let in_slice = unsafe { std::slice::from_raw_parts(in_buf as *const u8, in_bufsz) };
    match get_ops::<T>(&req).ioctl(
        FuseReq { req },
        ino,
        cmd,
        arg,
        unsafe { fi.as_ref() },
        flags,
        in_slice,
        out_bufsz,
    ) {
        Ok((result, data)) => unsafe {
            fuse_reply_ioctl(req, result, data.as_ptr() as *const c_void, data.len());
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_forget_multi<T: FuseLowLevelOps>(
    req: fuse_req_t,
    count: usize,
    forgets: *mut fuse_forget_data,
) {
    let forgets = unsafe { std::slice::from_raw_parts(forgets, count) };
    match get_ops::<T>(&req).forget_multi(FuseReq { req }, forgets) {
        Ok(()) => unsafe {
            fuse_reply_none(req);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_flock<T: FuseLowLevelOps>(
    req: fuse_req_t,
    ino: fuse_ino_t,
    fi: *mut fuse_file_info,
    op: c_int,
) {
    match get_ops::<T>(&req).flock(FuseReq { req }, ino, unsafe { fi.as_ref() }, op) {
        Ok(()) => unsafe {
            fuse_reply_err(req, 0);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

pub fn generate_libfuse_low_level_ops<T: FuseLowLevelOps>(ops: &T) -> bindings::fuse_lowlevel_ops {
    let mut fuse_ops: bindings::fuse_lowlevel_ops = unsafe { std::mem::zeroed() };
    fuse_ops.init = Some(rs_init::<T>);

    if ops.can_lookup() {
        fuse_ops.lookup = Some(rs_lookup::<T>);
    }
    if ops.can_forget() {
        fuse_ops.forget = Some(rs_forget::<T>);
    }
    if ops.can_getattr() {
        fuse_ops.getattr = Some(rs_getattr::<T>);
    }
    if ops.can_setattr() {
        fuse_ops.setattr = Some(rs_setattr::<T>);
    }
    if ops.can_readlink() {
        fuse_ops.readlink = Some(rs_readlink::<T>);
    }
    if ops.can_mknod() {
        fuse_ops.mknod = Some(rs_mknod::<T>);
    }
    if ops.can_mkdir() {
        fuse_ops.mkdir = Some(rs_mkdir::<T>);
    }
    if ops.can_unlink() {
        fuse_ops.unlink = Some(rs_unlink::<T>);
    }
    if ops.can_rmdir() {
        fuse_ops.rmdir = Some(rs_rmdir::<T>);
    }
    if ops.can_symlink() {
        fuse_ops.symlink = Some(rs_symlink::<T>);
    }
    if ops.can_rename() {
        fuse_ops.rename = Some(rs_rename::<T>);
    }
    if ops.can_link() {
        fuse_ops.link = Some(rs_link::<T>);
    }
    if ops.can_open() {
        fuse_ops.open = Some(rs_open::<T>);
    }
    if ops.can_read() {
        fuse_ops.read = Some(rs_read::<T>);
    }
    if ops.can_write() {
        fuse_ops.write = Some(rs_write::<T>);
    }
    if ops.can_flush() {
        fuse_ops.flush = Some(rs_flush::<T>);
    }
    if ops.can_release() {
        fuse_ops.release = Some(rs_release::<T>);
    }
    if ops.can_fsync() {
        fuse_ops.fsync = Some(rs_fsync::<T>);
    }
    if ops.can_opendir() {
        fuse_ops.opendir = Some(rs_opendir::<T>);
    }
    if ops.can_readdir() {
        fuse_ops.readdir = Some(rs_readdir::<T>);
    }
    if ops.can_releasedir() {
        fuse_ops.releasedir = Some(rs_releasedir::<T>);
    }
    if ops.can_fsyncdir() {
        fuse_ops.fsyncdir = Some(rs_fsyncdir::<T>);
    }
    if ops.can_statfs() {
        fuse_ops.statfs = Some(rs_statfs::<T>);
    }
    if ops.can_setxattr() {
        fuse_ops.setxattr = Some(rs_setxattr::<T>);
    }
    if ops.can_getxattr() {
        fuse_ops.getxattr = Some(rs_getxattr::<T>);
    }
    if ops.can_listxattr() {
        fuse_ops.listxattr = Some(rs_listxattr::<T>);
    }
    if ops.can_removexattr() {
        fuse_ops.removexattr = Some(rs_removexattr::<T>);
    }
    if ops.can_access() {
        fuse_ops.access = Some(rs_access::<T>);
    }
    if ops.can_create() {
        fuse_ops.create = Some(rs_create::<T>);
    }
    if ops.can_getlk() {
        fuse_ops.getlk = Some(rs_getlk::<T>);
    }
    if ops.can_setlk() {
        fuse_ops.setlk = Some(rs_setlk::<T>);
    }
    if ops.can_bmap() {
        fuse_ops.bmap = Some(rs_bmap::<T>);
    }
    if ops.can_ioctl() {
        fuse_ops.ioctl = Some(rs_ioctl::<T>);
    }
    if ops.can_forget_multi() {
        fuse_ops.forget_multi = Some(rs_forget_multi::<T>);
    }
    if ops.can_flock() {
        fuse_ops.flock = Some(rs_flock::<T>);
    }
    fuse_ops
}

fn extract_errno(e: &anyhow::Error) -> c_int {
    if let Some(errno) = e.downcast_ref::<rustix::io::Errno>() {
        return errno.raw_os_error();
    }
    if let Some(e) = e.downcast_ref::<std::io::Error>() {
        return e.raw_os_error().unwrap_or(Errno::IO.raw_os_error());
    }
    if e.downcast_ref::<INodeNotFoundError>().is_some() {
        return Errno::NOENT.raw_os_error();
    }
    Errno::IO.raw_os_error()
}

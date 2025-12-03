use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_int, c_uint, c_void},
};

use rustix::io::Errno;

use crate::fuse_wrappers::bindings::{
    self, fuse_bufvec, fuse_conn_info, fuse_file_info, fuse_ino_t, fuse_pollhandle,
    fuse_reply_attr, fuse_reply_bmap, fuse_reply_buf, fuse_reply_create, fuse_reply_entry,
    fuse_reply_err, fuse_reply_lock, fuse_reply_lseek, fuse_reply_none, fuse_reply_open,
    fuse_reply_readlink, fuse_reply_statfs, fuse_reply_write, fuse_req_t, fuse_req_userdata,
};

pub trait FuseLowLevelOps {
    fn init(&mut self, conn: &fuse_conn_info);
    fn can_lookup(&self) -> bool {
        false
    }
    fn lookup(&self, parent: u64, name: &CStr) -> anyhow::Result<bindings::fuse_entry_param> {
        unimplemented!()
    }
    fn can_forget(&self) -> bool {
        false
    }
    fn forget(&self, ino: u64, nlookup: u64) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_geattr(&self) -> bool {
        false
    }
    fn getattr(
        &self,
        ino: u64,
        fi: &mut bindings::fuse_file_info,
    ) -> anyhow::Result<(bindings::stat, f64)> {
        unimplemented!()
    }
    fn can_setattr(&self) -> bool {
        false
    }
    fn setattr(
        &self,
        ino: u64,
        attr: &mut bindings::stat,
        to_set: i32,
        fi: &mut bindings::fuse_file_info,
    ) -> anyhow::Result<(bindings::stat, f64)> {
        unimplemented!()
    }
    fn can_readlink(&self) -> bool {
        false
    }
    fn readlink(&self, ino: u64) -> anyhow::Result<CString> {
        unimplemented!()
    }
    fn can_mknod(&self) -> bool {
        false
    }
    fn mknod(
        &self,
        parent: u64,
        name: &CStr,
        mode: u32,
        rdev: u64,
    ) -> anyhow::Result<bindings::fuse_entry_param> {
        unimplemented!()
    }
    fn can_mkdir(&self) -> bool {
        false
    }
    fn mkdir(
        &self,
        parent: u64,
        name: &CStr,
        mode: u32,
    ) -> anyhow::Result<bindings::fuse_entry_param> {
        unimplemented!()
    }
    fn can_unlink(&self) -> bool {
        false
    }
    fn unlink(&self, parent: u64, name: &CStr) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_rmdir(&self) -> bool {
        false
    }
    fn rmdir(&self, parent: u64, name: &CStr) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_symlink(&self) -> bool {
        false
    }
    fn symlink(
        &self,
        link: &CStr,
        parent: u64,
        name: &CStr,
    ) -> anyhow::Result<bindings::fuse_entry_param> {
        unimplemented!()
    }
    fn can_rename(&self) -> bool {
        false
    }
    fn rename(
        &self,
        parent: u64,
        name: &CStr,
        newparent: u64,
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
        ino: u64,
        newparent: u64,
        newname: &CStr,
    ) -> anyhow::Result<bindings::fuse_entry_param> {
        unimplemented!()
    }
    fn can_open(&self) -> bool {
        false
    }
    fn open(&self, ino: u64, fi: &mut bindings::fuse_file_info) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_read(&self) -> bool {
        false
    }
    fn read(
        &self,
        ino: u64,
        size: usize,
        off: i64,
        fi: &mut bindings::fuse_file_info,
    ) -> anyhow::Result<&[u8]> {
        unimplemented!()
    }
    fn can_write(&self) -> bool {
        false
    }
    fn write(
        &self,
        ino: u64,
        buf: &[u8],
        off: i64,
        fi: &mut bindings::fuse_file_info,
    ) -> anyhow::Result<usize> {
        unimplemented!()
    }
    fn can_flush(&self) -> bool {
        false
    }
    fn flush(&self, ino: u64, fi: &mut bindings::fuse_file_info) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_release(&self) -> bool {
        false
    }
    fn release(&self, ino: u64, fi: &mut bindings::fuse_file_info) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn can_fsync(&self) -> bool {
        false
    }
    fn fsync(
        &self,
        ino: u64,
        datasync: i32,
        fi: &mut bindings::fuse_file_info,
    ) -> anyhow::Result<()> {
        unimplemented!()
    }
}

fn get_user_data(req: &fuse_req_t) -> &Box<dyn FuseLowLevelOps> {
    unsafe {
        { fuse_req_userdata(*req) as usize as *const Box<dyn FuseLowLevelOps> }
            .as_ref()
            .unwrap()
    }
}

extern "C" fn rs_init(userdata: *mut ::std::os::raw::c_void, conn: *mut fuse_conn_info) {
    unsafe {
        let userdata = userdata as usize as *mut Box<dyn FuseLowLevelOps>;
        let userdata = userdata.as_mut().unwrap();
        userdata.init(conn.as_mut().unwrap());
    }
}

extern "C" fn rs_lookup(req: fuse_req_t, parent: fuse_ino_t, name: *const ::std::os::raw::c_char) {
    let name = unsafe { CStr::from_ptr(name) };
    match get_user_data(&req).lookup(parent, name) {
        Ok(entry) => unsafe {
            fuse_reply_entry(req, &entry);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_forget(req: fuse_req_t, ino: fuse_ino_t, nlookup: u64) {
    match get_user_data(&req).forget(ino, nlookup) {
        Ok(_) => unsafe {
            fuse_reply_none(req);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_getattr(req: fuse_req_t, ino: fuse_ino_t, fi: *mut fuse_file_info) {
    match get_user_data(&req).getattr(ino, unsafe { fi.as_mut().unwrap() }) {
        Ok((stat, timeout)) => unsafe {
            fuse_reply_attr(req, &stat, timeout);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_setattr(
    req: fuse_req_t,
    ino: fuse_ino_t,
    attr: *mut bindings::stat,
    to_set: c_int,
    fi: *mut fuse_file_info,
) {
    match get_user_data(&req).setattr(ino, unsafe { attr.as_mut().unwrap() }, to_set, unsafe {
        fi.as_mut().unwrap()
    }) {
        Ok((stat, timeout)) => unsafe {
            fuse_reply_attr(req, &stat, timeout);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_readlink(req: fuse_req_t, ino: fuse_ino_t) {
    match get_user_data(&req).readlink(ino) {
        Ok(link) => unsafe {
            fuse_reply_readlink(req, link.as_ptr());
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_mknod(
    req: fuse_req_t,
    parent: fuse_ino_t,
    name: *const c_char,
    mode: u32,
    rdev: u64,
) {
    let name = unsafe { CStr::from_ptr(name) };
    match get_user_data(&req).mknod(parent, name, mode, rdev) {
        Ok(entry) => unsafe {
            fuse_reply_entry(req, &entry);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_mkdir(req: fuse_req_t, parent: fuse_ino_t, name: *const c_char, mode: u32) {
    let name = unsafe { CStr::from_ptr(name) };
    match get_user_data(&req).mkdir(parent, name, mode) {
        Ok(entry) => unsafe {
            fuse_reply_entry(req, &entry);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_unlink(req: fuse_req_t, parent: fuse_ino_t, name: *const c_char) {
    let name = unsafe { CStr::from_ptr(name) };
    match get_user_data(&req).unlink(parent, name) {
        Ok(()) => unsafe {
            fuse_reply_err(req, 0);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_rmdir(req: fuse_req_t, parent: fuse_ino_t, name: *const c_char) {
    let name = unsafe { CStr::from_ptr(name) };
    match get_user_data(&req).rmdir(parent, name) {
        Ok(()) => unsafe {
            fuse_reply_err(req, 0);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_symlink(
    req: fuse_req_t,
    link: *const c_char,
    parent: fuse_ino_t,
    name: *const c_char,
) {
    let link = unsafe { CStr::from_ptr(link) };
    let name = unsafe { CStr::from_ptr(name) };
    match get_user_data(&req).symlink(link, parent, name) {
        Ok(entry) => unsafe {
            fuse_reply_entry(req, &entry);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_rename(
    req: fuse_req_t,
    parent: fuse_ino_t,
    name: *const c_char,
    newparent: fuse_ino_t,
    newname: *const c_char,
    flags: c_uint,
) {
    let name = unsafe { CStr::from_ptr(name) };
    let newname = unsafe { CStr::from_ptr(newname) };
    match get_user_data(&req).rename(parent, name, newparent, newname, flags) {
        Ok(()) => unsafe {
            fuse_reply_err(req, 0);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_link(
    req: fuse_req_t,
    ino: fuse_ino_t,
    newparent: fuse_ino_t,
    newname: *const c_char,
) {
    let newname = unsafe { CStr::from_ptr(newname) };
    match get_user_data(&req).link(ino, newparent, newname) {
        Ok(entry) => unsafe {
            fuse_reply_entry(req, &entry);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_open(req: fuse_req_t, ino: fuse_ino_t, fi: *mut fuse_file_info) {
    match get_user_data(&req).open(ino, unsafe { fi.as_mut().unwrap() }) {
        Ok(()) => unsafe {
            fuse_reply_open(req, fi);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_read(
    req: fuse_req_t,
    ino: fuse_ino_t,
    size: usize,
    off: i64,
    fi: *mut fuse_file_info,
) {
    match get_user_data(&req).read(ino, size, off, unsafe { fi.as_mut().unwrap() }) {
        Ok(data) => unsafe {
            fuse_reply_buf(req, data.as_ptr() as *const c_char, data.len());
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_write(
    req: fuse_req_t,
    ino: fuse_ino_t,
    buf: *const c_char,
    size: usize,
    off: i64,
    fi: *mut fuse_file_info,
) {
    let slice = unsafe { std::slice::from_raw_parts(buf as *const u8, size) };
    match get_user_data(&req).write(ino, slice, off, unsafe { fi.as_mut().unwrap() }) {
        Ok(written) => unsafe {
            fuse_reply_write(req, written);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_flush(req: fuse_req_t, ino: fuse_ino_t, fi: *mut fuse_file_info) {
    match get_user_data(&req).flush(ino, unsafe { fi.as_mut().unwrap() }) {
        Ok(()) => unsafe {
            fuse_reply_err(req, 0);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_release(req: fuse_req_t, ino: fuse_ino_t, fi: *mut fuse_file_info) {
    match get_user_data(&req).release(ino, unsafe { fi.as_mut().unwrap() }) {
        Ok(()) => unsafe {
            fuse_reply_err(req, 0);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

extern "C" fn rs_fsync(req: fuse_req_t, ino: fuse_ino_t, datasync: c_int, fi: *mut fuse_file_info) {
    match get_user_data(&req).fsync(ino, datasync, unsafe { fi.as_mut().unwrap() }) {
        Ok(()) => unsafe {
            fuse_reply_err(req, 0);
        },
        Err(e) => unsafe {
            fuse_reply_err(req, extract_errno(&e));
        },
    }
}

pub fn generate_libfuse_low_level_ops(
    ops: Box<Box<dyn FuseLowLevelOps>>,
) -> bindings::fuse_lowlevel_ops {
    let mut fuse_ops: bindings::fuse_lowlevel_ops = unsafe { std::mem::zeroed() };
    fuse_ops.init = Some(rs_init);

    if ops.can_lookup() {
        fuse_ops.lookup = Some(rs_lookup);
    }
    if ops.can_forget() {
        fuse_ops.forget = Some(rs_forget);
    }
    if ops.can_geattr() {
        fuse_ops.getattr = Some(rs_getattr);
    }
    if ops.can_setattr() {
        fuse_ops.setattr = Some(rs_setattr);
    }
    if ops.can_readlink() {
        fuse_ops.readlink = Some(rs_readlink);
    }
    if ops.can_mknod() {
        fuse_ops.mknod = Some(rs_mknod);
    }
    if ops.can_mkdir() {
        fuse_ops.mkdir = Some(rs_mkdir);
    }
    if ops.can_unlink() {
        fuse_ops.unlink = Some(rs_unlink);
    }
    if ops.can_rmdir() {
        fuse_ops.rmdir = Some(rs_rmdir);
    }
    if ops.can_symlink() {
        fuse_ops.symlink = Some(rs_symlink);
    }
    if ops.can_rename() {
        fuse_ops.rename = Some(rs_rename);
    }
    if ops.can_link() {
        fuse_ops.link = Some(rs_link);
    }
    if ops.can_open() {
        fuse_ops.open = Some(rs_open);
    }
    if ops.can_read() {
        fuse_ops.read = Some(rs_read);
    }
    if ops.can_write() {
        fuse_ops.write = Some(rs_write);
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
    Errno::IO.raw_os_error()
}

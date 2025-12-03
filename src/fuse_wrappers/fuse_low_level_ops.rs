use std::{ffi::CStr, os::raw::c_int};

use rustix::io::Errno;

use crate::fuse_wrappers::bindings::{
    self, fuse_conn_info, fuse_file_info, fuse_ino_t, fuse_reply_attr, fuse_reply_entry,
    fuse_reply_err, fuse_reply_none, fuse_req_t, fuse_req_userdata,
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

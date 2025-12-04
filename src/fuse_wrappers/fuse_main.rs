use std::{ffi::CStr, fmt::Display, os::raw::c_void};

use scopeguard::defer;

use crate::fuse_wrappers::{
    bindings::{
        self, fuse_args, fuse_cmdline_opts, fuse_opt_free_args, fuse_parse_cmdline,
        fuse_remove_signal_handlers, fuse_session_destroy, fuse_session_mount, fuse_session_new,
        fuse_session_unmount, fuse_set_signal_handlers,
    },
    fuse_low_level_ops::{FuseLowLevelOps, generate_libfuse_low_level_ops},
};

#[derive(Debug)]
pub struct FuseInitError;

impl Display for FuseInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("fuse init failed")
    }
}
impl std::error::Error for FuseInitError {}

pub fn run_fuse_main(
    fuse_args: &[&CStr],
    ops: &mut Box<Box<dyn FuseLowLevelOps>>,
) -> anyhow::Result<()> {
    let mut c_args: Vec<*mut std::os::raw::c_char> =
        fuse_args.iter().map(|s| s.as_ptr().cast_mut()).collect();
    let mut cmdline_opts = scopeguard::guard(
        unsafe { std::mem::zeroed::<fuse_cmdline_opts>() },
        |opt| unsafe {
            libc::free(opt.mountpoint as *mut c_void);
        },
    );
    let mut fuse_args = scopeguard::guard(
        fuse_args {
            argc: c_args.len() as i32,
            argv: c_args.as_mut_ptr(),
            allocated: 0,
        },
        |mut a| unsafe {
            fuse_opt_free_args(&mut a);
        },
    );
    if unsafe { fuse_parse_cmdline(&mut *fuse_args, &mut *cmdline_opts) } < 0 {
        Err(FuseInitError {})?;
    }
    let fuse_ops = generate_libfuse_low_level_ops(ops);
    let session = scopeguard::guard(
        unsafe {
            fuse_session_new(
                &mut *fuse_args,
                &fuse_ops,
                size_of::<bindings::fuse_lowlevel_ops>(),
                &raw mut *ops as *mut c_void,
            )
        },
        |s| unsafe {
            if s.is_null() {
                return;
            }
            fuse_session_destroy(s);
        },
    );
    if session.is_null() {
        Err(FuseInitError {})?;
    }
    if unsafe { fuse_set_signal_handlers(*session) } != 0 {
        Err(FuseInitError {})?;
    }
    defer!(unsafe {
        fuse_remove_signal_handlers(*session);
    });
    if unsafe { fuse_session_mount(*session, cmdline_opts.mountpoint) } != 0 {
        Err(FuseInitError {})?;
    }
    defer!(unsafe { fuse_session_unmount(*session) });

    Ok(())
}

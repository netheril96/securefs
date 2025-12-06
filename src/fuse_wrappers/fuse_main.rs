use std::{ffi::CStr, fmt::Display, os::raw::c_void};

use anyhow::Context;
use scopeguard::defer;

use crate::fuse_wrappers::{
    bindings::{
        self, fuse_args, fuse_cmdline_opts, fuse_lowlevel_ops, fuse_opt_free_args,
        fuse_parse_cmdline, fuse_remove_signal_handlers, fuse_session, fuse_session_destroy,
        fuse_session_loop_mt, fuse_session_mount, fuse_session_unmount, fuse_set_signal_handlers,
    },
    fuse_low_level_ops::{FuseLowLevelOps, generate_libfuse_low_level_ops},
};

#[derive(Debug)]
pub struct FuseLoopError;

impl Display for FuseLoopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("fuse loop failed")
    }
}
impl std::error::Error for FuseLoopError {}

// Redeclare this instead of relying on bindgen.
// This is because on newer libfuse (e.g. 3.17) the symbol is not declared in the header file.
// For compatibility we always call this function.
unsafe extern "C" {
    #[doc = " Create a low level session.\n\n Returns a session structure suitable for passing to\n fuse_session_mount() and fuse_session_loop().\n\n This function accepts most file-system independent mount options\n (like context, nodev, ro - see mount(8)), as well as the general\n fuse mount options listed in mount.fuse(8) (e.g. -o allow_root and\n -o default_permissions, but not ``-o use_ino``).  Instead of `-o\n debug`, debugging may also enabled with `-d` or `--debug`.\n\n If not all options are known, an error message is written to stderr\n and the function returns NULL.\n\n Option parsing skips argv[0], which is assumed to contain the\n program name. To prevent accidentally passing an option in\n argv[0], this element must always be present (even if no options\n are specified). It may be set to the empty string ('\\0') if no\n reasonable value can be provided.\n\n @param args argument vector\n @param op the (low-level) filesystem operations\n @param op_size sizeof(struct fuse_lowlevel_ops)\n @param userdata user data\n\n @return the fuse session on success, NULL on failure"]
    pub fn fuse_session_new(
        args: *mut fuse_args,
        op: *const fuse_lowlevel_ops,
        op_size: usize,
        userdata: *mut ::std::os::raw::c_void,
    ) -> *mut fuse_session;
}

pub fn run_fuse_main<T: FuseLowLevelOps>(
    fuse_args: &[&CStr],
    ops: &mut Box<T>,
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
        Err(FuseLoopError {})?;
    }
    let fuse_ops = generate_libfuse_low_level_ops(&mut **ops);
    let userdata: *mut T = &raw mut **ops;
    let session = scopeguard::guard(
        unsafe {
            fuse_session_new(
                &mut *fuse_args,
                &fuse_ops,
                size_of::<bindings::fuse_lowlevel_ops>(),
                userdata as _,
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
        Err(FuseLoopError {})?;
    }
    if unsafe { fuse_set_signal_handlers(*session) } != 0 {
        Err(FuseLoopError {})?;
    }
    defer!(unsafe {
        fuse_remove_signal_handlers(*session);
    });
    if unsafe { fuse_session_mount(*session, cmdline_opts.mountpoint) } != 0 {
        Err(FuseLoopError {})?;
    }
    defer!(unsafe { fuse_session_unmount(*session) });

    let ret = unsafe { fuse_session_loop_mt(*session, std::ptr::null_mut()) };
    if ret != 0 {
        return Err(FuseLoopError).with_context(|| format!("fuse_session_loop_mt returns {ret}"));
    }
    log::info!("fuse_session_loop_mt returned {ret}");
    Ok(())
}

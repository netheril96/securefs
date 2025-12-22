#![allow(dead_code)] // Disables the linting until everything is wired together
#![allow(unused_variables)]

use ambassador::delegatable_trait;

pub mod aesgcm;
pub mod fuse_wrappers;
pub mod lite;
pub mod params_io;
pub mod protos;
pub mod rng;
pub mod stream;
pub mod tearc;
pub mod vfs;
pub mod win;
pub mod winfsp_wrappers;

pub type MasterKeyType = [u8; 32];

#[cfg(unix)]
pub type OwnedFileDescriptor = std::os::fd::OwnedFd;
#[cfg(unix)]
pub type BorrowedFileDescriptor<'a> = std::os::fd::BorrowedFd<'a>;

#[cfg(windows)]
pub type OwnedFileDescriptor = std::os::windows::io::OwnedHandle;
#[cfg(windows)]
pub type BorrowedFileDescriptor<'a> = std::os::windows::io::BorrowedHandle<'a>;

#[delegatable_trait]
pub trait WriteUpgradable {
    fn upgrade_to_writable(&mut self) -> anyhow::Result<()>;
}

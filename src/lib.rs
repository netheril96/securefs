#![allow(dead_code)] // Disables the linting until everything is wired together
#![allow(unused_variables)]

pub mod aesgcm;
pub mod error;
pub mod fuse_wrappers;
pub mod lite;
pub mod protos;
pub mod rng;
pub mod stream;
pub mod vfs;

pub type MasterKeyType = [u8; 32];

#[cfg(unix)]
pub type OwnedFileDescriptor = std::os::fd::OwnedFd;
#[cfg(unix)]
pub type BorrowedFileDescriptor<'a> = std::os::fd::BorrowedFd<'a>;

#[cfg(windows)]
pub type OwnedFileDescriptor = std::os::windows::io::OwnedHandle;
#[cfg(windows)]
pub type BorrowedFileDescriptor<'a> = std::os::windows::io::BorrowedHandle<'a>;

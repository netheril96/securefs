#![allow(dead_code)] // Disables the linting until everything is wired together
#![allow(unused_variables)]

pub mod aesgcm;
pub mod error;
pub mod fuse_wrappers;
pub mod lite;
pub mod protos;
pub mod stream;
pub mod vfs;

pub type MasterKeyType = [u8; 32];

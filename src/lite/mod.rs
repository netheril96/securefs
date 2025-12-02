#[cfg(unix)]
use std::os::fd::{BorrowedFd, OwnedFd};

use crate::stream::Stream;

pub mod fuse;
pub mod name_translators;
pub mod unix;

#[cfg(unix)]
pub trait IoWrapperStream: Stream {
    fn as_fd(&self) -> BorrowedFd<'_>;
    fn replace_fd(&mut self, fd: OwnedFd);
}

#[cfg(unix)]
pub trait IoWrapperFactory {
    fn compute_virtual_size(&self, underlying_size: u64) -> Option<u64>;
    fn wrap(&self, fd: OwnedFd) -> anyhow::Result<Box<dyn IoWrapperStream>>;
}

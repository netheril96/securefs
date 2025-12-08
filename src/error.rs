#[cfg(windows)]
use thiserror::Error;

#[cfg(windows)]
#[derive(Debug, Error)]
#[error("NTSTATUS 0x{status:0x}")]
pub struct NtError {
    pub status: i32,
}

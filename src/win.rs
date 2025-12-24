#![cfg(windows)]

use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::System::WindowsProgramming::RtlInitUnicodeString;
use windows::{Win32::Foundation::UNICODE_STRING, core::PWSTR};

use thiserror::Error;
use winfsp::U16CString;

use crate::AssertOk;

#[derive(Debug, Error)]
#[error("NTSTATUS 0x{:0x}", status.0)]
pub struct NtError {
    pub status: NTSTATUS,
}

pub struct OwnedUnicodeString {
    pub u16cstr: U16CString,
    pub unicode_string: UNICODE_STRING,
}

impl TryFrom<&str> for OwnedUnicodeString {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut u16cstr = U16CString::from_str(value)?;
        let mut un = UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: PWSTR::null(),
        };
        unsafe {
            RtlInitUnicodeString(&raw mut un, PWSTR::from_raw(u16cstr.as_mut_ptr()));
        }
        Ok(Self {
            u16cstr,
            unicode_string: un,
        })
    }
}

impl TryFrom<&[u8]> for OwnedUnicodeString {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(str::from_utf8(value)?)
    }
}

impl AssertOk for NTSTATUS {
    fn assert_ok(&self) -> anyhow::Result<()> {
        if self.is_ok() {
            Ok(())
        } else {
            Err(NtError { status: *self })?
        }
    }
}

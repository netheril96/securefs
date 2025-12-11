#![cfg(windows)]

use anyhow::bail;
use windows::Win32::Foundation::{NTSTATUS, STATUS_UNSUCCESSFUL};
use windows::{Win32::Foundation::UNICODE_STRING, core::PWSTR};

use thiserror::Error;

#[derive(Debug, Error)]
#[error("NTSTATUS 0x{:0x}", status.0)]
pub struct NtError {
    pub status: NTSTATUS,
}

pub struct OwnedUnicodeString {
    pub utf16str: Vec<u16>,
    pub unicode_string: UNICODE_STRING,
}

impl TryFrom<&str> for OwnedUnicodeString {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let utf16str: Vec<u16> = value.encode_utf16().collect();
        if utf16str.len() >= u16::MAX.into() {
            bail!("string too long ({}) for NT API", utf16str.len());
        }
        let un = UNICODE_STRING {
            Length: utf16str.len() as u16,
            MaximumLength: utf16str.len() as u16,
            Buffer: PWSTR(utf16str.as_ptr().cast_mut()),
        };
        Ok(Self {
            utf16str,
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

pub fn to_winfsp_error(e: &anyhow::Error) -> winfsp::FspError {
    if let Some(e) = e.downcast_ref::<NtError>() {
        return winfsp::FspError::NTSTATUS(e.status.0);
    }
    if let Some(e) = e.downcast_ref::<std::io::Error>()
        && let Some(code) = e.raw_os_error()
    {
        return winfsp::FspError::WIN32(code as _);
    }

    return winfsp::FspError::NTSTATUS(STATUS_UNSUCCESSFUL.0);
}

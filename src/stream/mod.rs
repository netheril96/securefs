pub mod block;
pub mod lite;

use std::fs::File;
use std::io::Write;
use std::{cmp::min, usize};

// On unix, we can use pread/pwrite
#[cfg(unix)]
use std::os::unix::fs::FileExt;

// On windows, we can use seek_read/seek_write
#[cfg(windows)]
use std::os::windows::fs::FileExt;

use ambassador::delegatable_trait;
use anyhow::Ok;
use thiserror::Error;

#[allow(unused)]
use crate::OwnedFileDescriptor;

pub type OffsetType = u64;
pub type LengthType = u64;

#[allow(unused)]
#[delegatable_trait]
pub trait Stream {
    fn read(&mut self, buffer: &mut [u8], offset: OffsetType) -> anyhow::Result<LengthType>;
    fn write(&mut self, buffer: &[u8], offset: OffsetType) -> anyhow::Result<()>;
    fn size(&self) -> anyhow::Result<LengthType>;
    fn flush(&mut self) -> anyhow::Result<()>;
    fn resize(&mut self, size: LengthType) -> anyhow::Result<()>;
    fn is_sparse(&self) -> bool {
        false
    }
    fn optimal_block_size(&self) -> LengthType {
        1
    }
}

pub struct MemoryStream {
    buffer: Vec<u8>,
}

impl Stream for MemoryStream {
    fn read(&mut self, buffer: &mut [u8], offset: OffsetType) -> anyhow::Result<LengthType> {
        if buffer.is_empty() || offset >= self.buffer.len().try_into()? {
            return Ok(0);
        }
        let slice = &self.buffer
            [offset.try_into()?..min(usize::try_from(offset)? + buffer.len(), self.buffer.len())];
        let (to_be_copied, _) = buffer.split_at_mut(slice.len());
        to_be_copied.copy_from_slice(slice);
        Ok(slice.len().try_into()?)
    }

    fn write(&mut self, buffer: &[u8], offset: OffsetType) -> anyhow::Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }
        let end: u64 = offset + u64::try_from(buffer.len())?;
        if end > self.buffer.len().try_into()? {
            self.buffer.resize(end.try_into()?, 0);
        }
        let slice = &mut self.buffer[offset.try_into()?..end.try_into()?];
        slice.copy_from_slice(buffer);
        Ok(())
    }

    fn size(&self) -> anyhow::Result<LengthType> {
        Ok(self.buffer.len().try_into()?)
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn resize(&mut self, size: LengthType) -> anyhow::Result<()> {
        self.buffer.resize(size.try_into()?, 0);
        Ok(())
    }
}

pub struct StdIoStream {
    file: File,
}

impl StdIoStream {
    pub fn new(file: File) -> StdIoStream {
        StdIoStream { file }
    }
}

impl From<File> for StdIoStream {
    fn from(value: File) -> Self {
        Self { file: value }
    }
}

impl From<OwnedFileDescriptor> for StdIoStream {
    fn from(value: OwnedFileDescriptor) -> Self {
        Self::from(File::from(value))
    }
}

impl AsRef<File> for StdIoStream {
    fn as_ref(&self) -> &File {
        &self.file
    }
}

impl Stream for StdIoStream {
    #[cfg(unix)]
    fn read(&mut self, buffer: &mut [u8], offset: OffsetType) -> anyhow::Result<LengthType> {
        Ok(self.file.read_at(buffer, offset)?.try_into()?)
    }

    #[cfg(windows)]
    fn read(&mut self, buffer: &mut [u8], offset: OffsetType) -> anyhow::Result<LengthType> {
        Ok(self.file.seek_read(buffer, offset)?.try_into()?)
    }

    #[cfg(unix)]
    fn write(&mut self, buffer: &[u8], offset: OffsetType) -> anyhow::Result<()> {
        self.file.write_all_at(buffer, offset)?;
        Ok(())
    }

    #[cfg(windows)]
    fn write(&mut self, mut buffer: &[u8], mut offset: OffsetType) -> anyhow::Result<()> {
        while !buffer.is_empty() {
            let bytes_written = self.file.seek_write(buffer, offset)?;
            if bytes_written == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write any data",
                ))?;
            }
            buffer = &buffer[bytes_written..];
            offset += LengthType::try_from(bytes_written)?;
        }
        Ok(())
    }

    fn size(&self) -> anyhow::Result<LengthType> {
        Ok(self.file.metadata()?.len())
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        self.file.flush()?;
        Ok(())
    }

    fn resize(&mut self, size: LengthType) -> anyhow::Result<()> {
        self.file.set_len(size)?;
        Ok(())
    }
}

#[delegatable_trait]
pub trait FileLockable {
    fn file_shared_lock(&mut self) -> anyhow::Result<()>;
    fn file_exclusive_lock(&mut self) -> anyhow::Result<()>;
    fn file_unlock(&mut self) -> anyhow::Result<()>;
}

impl FileLockable for StdIoStream {
    fn file_exclusive_lock(&mut self) -> anyhow::Result<()> {
        self.file.lock()?;
        Ok(())
    }

    fn file_shared_lock(&mut self) -> anyhow::Result<()> {
        self.file.lock_shared()?;
        Ok(())
    }

    fn file_unlock(&mut self) -> anyhow::Result<()> {
        self.file.unlock()?;
        Ok(())
    }
}

pub trait FileLockableStream: FileLockable + Stream {}

impl<T: FileLockable + Stream> FileLockableStream for T {}

pub struct ReadableStreamView<'a, T: FileLockableStream + ?Sized> {
    inner: &'a mut T,
}

impl<'a, T: FileLockableStream + ?Sized> ReadableStreamView<'a, T> {
    pub fn new(stream: &'a mut T) -> anyhow::Result<Self> {
        stream.file_shared_lock()?;
        Ok(Self { inner: stream })
    }

    pub fn read(&mut self, buffer: &mut [u8], offset: OffsetType) -> anyhow::Result<LengthType> {
        self.inner.read(buffer, offset)
    }

    pub fn size(&self) -> anyhow::Result<LengthType> {
        self.inner.size()
    }
}

impl<'a, T: FileLockableStream + ?Sized> Drop for ReadableStreamView<'a, T> {
    fn drop(&mut self) {
        if let Err(e) = self.inner.file_unlock() {
            log::error!("failed to unlock file from readable_view: {}", e);
        }
    }
}

pub struct WritableStreamView<'a, T: FileLockableStream + ?Sized> {
    inner: &'a mut T,
}

impl<'a, T: FileLockableStream + ?Sized> WritableStreamView<'a, T> {
    pub fn new(stream: &'a mut T) -> anyhow::Result<Self> {
        stream.file_exclusive_lock()?;
        Ok(Self { inner: stream })
    }

    pub fn write(&mut self, buffer: &[u8], offset: OffsetType) -> anyhow::Result<()> {
        self.inner.write(buffer, offset)
    }

    pub fn flush(&mut self) -> anyhow::Result<()> {
        self.inner.flush()
    }

    pub fn resize(&mut self, size: LengthType) -> anyhow::Result<()> {
        self.inner.resize(size)
    }
}

impl<'a, T: FileLockableStream + ?Sized> Drop for WritableStreamView<'a, T> {
    fn drop(&mut self) {
        if let Err(e) = self.inner.file_unlock() {
            log::error!("failed to unlock file from writable_view: {}", e);
        }
    }
}

enum LockStatus {
    Unlocked,
    LockedShared,
    LockedExclusively,
}

pub struct AssertLockedStream<T: FileLockable + Stream> {
    inner: T,
    lock_status: LockStatus,
}

impl<T: FileLockable + Stream> FileLockable for AssertLockedStream<T> {
    fn file_shared_lock(&mut self) -> anyhow::Result<()> {
        self.inner.file_shared_lock()?;
        self.lock_status = LockStatus::LockedShared;
        Ok(())
    }

    fn file_exclusive_lock(&mut self) -> anyhow::Result<()> {
        self.inner.file_exclusive_lock()?;
        self.lock_status = LockStatus::LockedExclusively;
        Ok(())
    }

    fn file_unlock(&mut self) -> anyhow::Result<()> {
        self.inner.file_unlock()?;
        self.lock_status = LockStatus::Unlocked;
        Ok(())
    }
}

impl<T: FileLockable + Stream> From<T> for AssertLockedStream<T> {
    fn from(value: T) -> Self {
        Self {
            inner: value,
            lock_status: LockStatus::Unlocked,
        }
    }
}

#[derive(Debug, Error)]
pub enum LockInapproriateError {
    #[error("should have acquired shared lock before calling method {method}")]
    ShouldAcquiredSharedLock { method: &'static str },
    #[error("should have acquired exclusive lock before calling method {method}")]
    ShouldAcquiredExclusiveLock { method: &'static str },
}

impl<T: FileLockable + Stream> Stream for AssertLockedStream<T> {
    fn read(&mut self, buffer: &mut [u8], offset: OffsetType) -> anyhow::Result<LengthType> {
        match self.lock_status {
            LockStatus::Unlocked => {
                Err(LockInapproriateError::ShouldAcquiredSharedLock { method: "read" }.into())
            }
            _ => self.inner.read(buffer, offset),
        }
    }

    fn write(&mut self, buffer: &[u8], offset: OffsetType) -> anyhow::Result<()> {
        match self.lock_status {
            LockStatus::LockedExclusively => self.inner.write(buffer, offset),
            _ => Err(LockInapproriateError::ShouldAcquiredExclusiveLock { method: "write" }.into()),
        }
    }

    fn size(&self) -> anyhow::Result<LengthType> {
        self.inner.size() // No lock needed
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        match self.lock_status {
            LockStatus::LockedExclusively => self.inner.flush(),
            _ => Err(LockInapproriateError::ShouldAcquiredExclusiveLock { method: "flush" }.into()),
        }
    }

    fn resize(&mut self, size: LengthType) -> anyhow::Result<()> {
        match self.lock_status {
            LockStatus::LockedExclusively => self.inner.resize(size),
            _ => {
                Err(LockInapproriateError::ShouldAcquiredExclusiveLock { method: "resize" }.into())
            }
        }
    }
}

#[cfg(windows)]
pub mod win {
    use crate::win::NtError;
    use crate::{
        OwnedFileDescriptor,
        stream::{FileLockable, LengthType, OffsetType, Stream},
    };
    use anyhow::bail;
    use windows::Wdk::Storage::FileSystem::{
        FILE_STANDARD_INFORMATION, FileEndOfFileInformation, FileStandardInformation,
        NtFlushBuffersFile, NtLockFile, NtQueryInformationFile, NtReadFile, NtSetInformationFile,
        NtUnlockFile, NtWriteFile,
    };
    use windows::Wdk::System::SystemServices::FILE_END_OF_FILE_INFORMATION;
    use windows::Win32::Foundation::{HANDLE, STATUS_END_OF_FILE};
    use windows::Win32::System::IO::IO_STATUS_BLOCK;

    use std::os::windows::io::AsRawHandle;
    use std::{i64, mem};

    pub struct NtFileStream {
        fd: OwnedFileDescriptor,
    }

    impl From<OwnedFileDescriptor> for NtFileStream {
        fn from(value: OwnedFileDescriptor) -> Self {
            Self { fd: value }
        }
    }

    impl NtFileStream {
        fn file_lock_common(&mut self, exclusive: bool) -> anyhow::Result<()> {
            let mut io_status_block: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
            let byte_offset: i64 = 0;
            let length = i64::MAX;

            let status = unsafe {
                NtLockFile(
                    HANDLE(self.fd.as_raw_handle()),
                    None,
                    None,
                    None,
                    &raw mut io_status_block,
                    &raw const byte_offset,
                    &raw const length,
                    0,
                    false,                                // FALSE, wait for lock
                    if exclusive { true } else { false }, // TRUE for exclusive lock
                )
            };
            if status.0 < 0 {
                return Err(NtError { status })?;
            }
            Ok(())
        }
    }

    impl FileLockable for NtFileStream {
        fn file_exclusive_lock(&mut self) -> anyhow::Result<()> {
            self.file_lock_common(true)
        }

        fn file_shared_lock(&mut self) -> anyhow::Result<()> {
            self.file_lock_common(false)
        }

        fn file_unlock(&mut self) -> anyhow::Result<()> {
            let mut io_status_block: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
            let byte_offset: i64 = 0;
            let length = i64::MAX;

            let status = unsafe {
                NtUnlockFile(
                    HANDLE(self.fd.as_raw_handle()),
                    &raw mut io_status_block,
                    &raw const byte_offset,
                    &raw const length,
                    0,
                )
            };
            if status.0 < 0 {
                return Err(NtError { status })?;
            }
            Ok(())
        }
    }

    impl Stream for NtFileStream {
        fn read(&mut self, buffer: &mut [u8], offset: OffsetType) -> anyhow::Result<LengthType> {
            let byte_offset = offset as i64;
            let mut io_status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };

            let rc = unsafe {
                NtReadFile(
                    HANDLE(self.fd.as_raw_handle()),
                    None,
                    None,
                    None,
                    &raw mut io_status_block,
                    buffer.as_mut_ptr() as _,
                    buffer.len().try_into()?,
                    Some(&raw const byte_offset),
                    None,
                )
            };

            if rc == STATUS_END_OF_FILE {
                return Ok(0);
            }

            if rc.0 < 0 {
                return Err(NtError { status: rc })?;
            }

            Ok(io_status_block.Information.try_into()?)
        }

        fn write(&mut self, buffer: &[u8], offset: OffsetType) -> anyhow::Result<()> {
            let byte_offset = offset as i64;
            let mut io_status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };

            let rc = unsafe {
                NtWriteFile(
                    HANDLE(self.fd.as_raw_handle()),
                    None,
                    None,
                    None,
                    &raw mut io_status_block,
                    buffer.as_ptr() as _,
                    buffer.len().try_into()?,
                    Some(&raw const byte_offset),
                    None,
                )
            };

            if rc.0 < 0 {
                return Err(NtError { status: rc })?;
            }
            if io_status_block.Information != buffer.len() {
                bail!("insufficient write");
            }
            Ok(())
        }

        fn size(&self) -> anyhow::Result<LengthType> {
            let mut io_status_block: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
            let mut file_info: FILE_STANDARD_INFORMATION = unsafe { mem::zeroed() };

            let status = unsafe {
                NtQueryInformationFile(
                    HANDLE(self.fd.as_raw_handle()),
                    &mut io_status_block,
                    &raw mut file_info as _,
                    mem::size_of::<FILE_STANDARD_INFORMATION>() as u32,
                    FileStandardInformation,
                )
            };

            if status.0 < 0 {
                return Err(NtError { status })?;
            }

            Ok(file_info.EndOfFile.try_into()?)
        }

        fn flush(&mut self) -> anyhow::Result<()> {
            let mut io_status_block: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
            let status = unsafe {
                NtFlushBuffersFile(HANDLE(self.fd.as_raw_handle()), &raw mut io_status_block)
            };
            if status.0 < 0 {
                return Err(NtError { status })?;
            }
            Ok(())
        }

        fn resize(&mut self, size: LengthType) -> anyhow::Result<()> {
            let mut io_status_block: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
            let file_info = FILE_END_OF_FILE_INFORMATION {
                EndOfFile: size.try_into()?,
            };

            let status = unsafe {
                NtSetInformationFile(
                    HANDLE(self.fd.as_raw_handle()),
                    &raw mut io_status_block,
                    &raw const file_info as _,
                    mem::size_of::<FILE_END_OF_FILE_INFORMATION>() as u32,
                    FileEndOfFileInformation,
                )
            };
            if status.0 < 0 {
                return Err(NtError { status })?;
            }
            Ok(())
        }
    }
}
#[cfg(test)]
pub mod test {
    use super::*;
    use rand::rng;
    use rand::{Rng, distr::Uniform, prelude::*};

    pub fn compare_with_reference(
        to_be_tested: &mut dyn Stream,
        reference: &mut dyn Stream,
        times: u32,
    ) -> anyhow::Result<()> {
        to_be_tested.resize(0)?;
        reference.resize(0)?;

        let mut data: Vec<u8> = Vec::new();
        data.resize(4096 * 5, 0);
        let mut buffer = data.clone();
        let mut memory_buffer = data.clone();

        let rng = &mut rng();

        for d in data.iter_mut() {
            *d = rng.random_range(0..=255);
        }

        let flag_dist = Uniform::try_from(0..5)?;
        let length_dist: Uniform<usize> = Uniform::try_from(0..7 * 4096 + 2)?;

        for _ in 0..times {
            match flag_dist.sample(rng) {
                0 => {
                    let offset = length_dist.sample(rng);
                    let length = min(data.len(), length_dist.sample(rng));
                    to_be_tested.write(&data[..length], offset.try_into()?)?;
                    reference.write(&data[..length], offset.try_into()?)?;
                }

                1 => {
                    let offset = length_dist.sample(rng);
                    let length = min(data.len(), length_dist.sample(rng));
                    let tested_read_size =
                        to_be_tested.read(&mut buffer[..length], offset.try_into()?)?;
                    let reference_read_size =
                        reference.read(&mut memory_buffer[..length], offset.try_into()?)?;
                    assert_eq!(tested_read_size, reference_read_size);
                    assert_eq!(&buffer[..length], &memory_buffer[..length]);
                }

                2 => {
                    assert_eq!(to_be_tested.size()?, reference.size()?);
                }

                3 => {
                    let length = length_dist.sample(rng);
                    to_be_tested.resize(length.try_into()?)?;
                    reference.resize(length.try_into()?)?;
                }
                4 => {
                    to_be_tested.flush()?;
                    reference.flush()?;
                }
                _ => panic!("unsupported flag"),
            }
        }

        Ok(())
    }

    #[test]
    fn test_std_io_stream() -> anyhow::Result<()> {
        let file = tempfile::NamedTempFile::new()?;
        let mut stdio_stream = StdIoStream::new(file.into_file());
        let mut memory_stream = MemoryStream { buffer: Vec::new() };
        compare_with_reference(&mut stdio_stream, &mut memory_stream, 500)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn test_nt_file_stream() -> anyhow::Result<()> {
        use std::os::windows::io::AsHandle;

        let file = tempfile::NamedTempFile::new()?;
        let mut nt_stream =
            win::NtFileStream::from(file.as_file().as_handle().try_clone_to_owned()?);
        let mut memory_stream = MemoryStream { buffer: Vec::new() };
        compare_with_reference(&mut nt_stream, &mut memory_stream, 500)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn test_assert_locked_nt_file_stream() -> anyhow::Result<()> {
        use std::os::windows::io::AsHandle;

        let file = tempfile::NamedTempFile::new()?;
        let nt_stream = win::NtFileStream::from(file.as_file().as_handle().try_clone_to_owned()?);
        let mut nt_stream = AssertLockedStream::from(nt_stream);
        let mut nt_stream = scopeguard::guard(
            {
                nt_stream.file_exclusive_lock()?;
                nt_stream
            },
            |mut nt_stream| {
                if let Err(e) = nt_stream.file_unlock() {
                    log::error!("failed to unlock file: {}", e);
                }
            },
        );
        let mut memory_stream = MemoryStream { buffer: Vec::new() };
        compare_with_reference(&mut *nt_stream, &mut memory_stream, 500)?;
        Ok(())
    }
}

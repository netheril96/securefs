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

#[cfg(windows)]
pub struct NtFileStream {
    fd: OwnedFileDescriptor,
}

#[cfg(windows)]
impl Stream for NtFileStream {
    fn read(&mut self, buffer: &mut [u8], offset: OffsetType) -> anyhow::Result<LengthType> {
        use ntapi::ntioapi::IO_STATUS_BLOCK;
        use ntapi::winapi::shared::ntstatus::STATUS_END_OF_FILE;

        let mut byte_offset: i64 = offset as _;
        let mut io_status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };

        let rc = unsafe {
            use std::os::windows::io::AsRawHandle;

            use ntapi::ntioapi::NtReadFile;

            NtReadFile(
                self.fd.as_raw_handle() as _,
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
                &raw mut io_status_block,
                buffer.as_mut_ptr() as _,
                buffer.len().try_into()?,
                &raw mut byte_offset as _,
                std::ptr::null_mut(),
            )
        };

        if rc == STATUS_END_OF_FILE {
            return Ok(0);
        }

        if rc < 0 {
            use crate::error::NtError;

            return Err(NtError { status: rc })?;
        }

        Ok(io_status_block.Information.try_into()?)
    }

    fn write(&mut self, buffer: &[u8], offset: OffsetType) -> anyhow::Result<()> {
        use ntapi::ntioapi::IO_STATUS_BLOCK;

        let mut byte_offset: i64 = offset as _;
        let mut io_status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };

        let rc = unsafe {
            use std::os::windows::io::AsRawHandle;

            use ntapi::ntioapi::NtWriteFile;

            NtWriteFile(
                self.fd.as_raw_handle() as _,
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
                &raw mut io_status_block,
                buffer.as_ptr().cast_mut() as _,
                buffer.len().try_into()?,
                &raw mut byte_offset as _,
                std::ptr::null_mut(),
            )
        };

        if rc < 0 {
            use crate::error::NtError;

            return Err(NtError { status: rc })?;
        }
        if io_status_block.Information != buffer.len() {
            use anyhow::bail;
            bail!("insufficient write");
        }
        Ok(())
    }

    fn size(&self) -> anyhow::Result<LengthType> {
        use crate::error::NtError;
        use ntapi::ntioapi::{
            FILE_STANDARD_INFORMATION, FileStandardInformation, IO_STATUS_BLOCK,
            NtQueryInformationFile,
        };
        use std::mem;
        use std::os::windows::io::AsRawHandle;

        let mut io_status_block: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
        let mut file_info: FILE_STANDARD_INFORMATION = unsafe { mem::zeroed() };

        let status = unsafe {
            NtQueryInformationFile(
                self.fd.as_raw_handle() as _,
                &mut io_status_block,
                &raw mut file_info as _,
                mem::size_of::<FILE_STANDARD_INFORMATION>() as u32,
                FileStandardInformation,
            )
        };

        if status < 0 {
            return Err(NtError { status })?;
        }

        Ok(unsafe { *file_info.EndOfFile.QuadPart() } as LengthType)
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        use crate::error::NtError;
        use ntapi::ntioapi::{IO_STATUS_BLOCK, NtFlushBuffersFile};
        use std::mem;
        use std::os::windows::io::AsRawHandle;

        let mut io_status_block: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
        let status =
            unsafe { NtFlushBuffersFile(self.fd.as_raw_handle() as _, &mut io_status_block) };
        if status < 0 {
            return Err(NtError { status })?;
        }
        Ok(())
    }

    fn resize(&mut self, size: LengthType) -> anyhow::Result<()> {
        use crate::error::NtError;
        use ntapi::ntioapi::{
            FILE_END_OF_FILE_INFORMATION, FileEndOfFileInformation, IO_STATUS_BLOCK,
            NtSetInformationFile,
        };
        use std::mem;
        use std::os::windows::io::AsRawHandle;

        let mut io_status_block: IO_STATUS_BLOCK = unsafe { mem::zeroed() };
        let mut file_info: FILE_END_OF_FILE_INFORMATION = unsafe { mem::zeroed() };
        unsafe {
            *file_info.EndOfFile.QuadPart_mut() = size.try_into()?;
        }

        let status = unsafe {
            NtSetInformationFile(
                self.fd.as_raw_handle() as _,
                &mut io_status_block,
                &raw mut file_info as _,
                mem::size_of::<FILE_END_OF_FILE_INFORMATION>() as u32,
                FileEndOfFileInformation,
            )
        };
        if status < 0 {
            return Err(NtError { status })?;
        }
        Ok(())
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
        let mut nt_stream = NtFileStream {
            fd: file.as_file().as_handle().try_clone_to_owned()?,
        };
        let mut memory_stream = MemoryStream { buffer: Vec::new() };
        compare_with_reference(&mut nt_stream, &mut memory_stream, 500)?;
        Ok(())
    }
}

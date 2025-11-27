mod block;
mod lite;

use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::{cmp::min, usize};

// On unix, we can use pread/pwrite
#[cfg(unix)]
use std::os::unix::fs::FileExt;

// On windows, we can use seek_read/seek_write
#[cfg(windows)]
use std::os::windows::fs::FileExt;

use anyhow::Ok;

type OffsetType = u64;
type LengthType = u64;

#[allow(unused)]
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
            [offset.try_into()?..min(offset as usize + buffer.len(), self.buffer.len())];
        let (to_be_copied, _) = buffer.split_at_mut(slice.len());
        to_be_copied.copy_from_slice(slice);
        Ok(slice.len().try_into()?)
    }

    fn write(&mut self, buffer: &[u8], offset: OffsetType) -> anyhow::Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }
        let end: u64 = offset + TryInto::<u64>::try_into(buffer.len())?;
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

    pub fn open<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<StdIoStream> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;
        Ok(StdIoStream::new(file))
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
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write any data",
                ))?;
            }
            buffer = &buffer[bytes_written..];
            offset += TryInto::<LengthType>::try_into(bytes_written)?;
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

#[cfg(test)]
pub mod test {
    use super::*;
    use rand::rng;
    use rand::{Rng, distr::Uniform, prelude::*};
    use std::env;
    use std::fs;

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
        let mut rng = rand::rng();
        let temp_file_path =
            env::temp_dir().join(format!("test_std_io_stream_{}.tmp", rng.next_u64()));
        println!("temp_file_path={:?}", temp_file_path);

        struct FileGuard<'a>(&'a std::path::Path);
        impl<'a> Drop for FileGuard<'a> {
            fn drop(&mut self) {
                let _ = fs::remove_file(self.0);
            }
        }
        let _guard = FileGuard(&temp_file_path);

        let mut stdio_stream = StdIoStream::open(&temp_file_path)?;
        let mut memory_stream = MemoryStream { buffer: Vec::new() };

        compare_with_reference(&mut stdio_stream, &mut memory_stream, 500)?;

        Ok(())
    }
}

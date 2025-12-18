use std::mem::size_of;

use aes_gcm::{Aes128Gcm, Key};
use ambassador::Delegate;
use anyhow::{Context, Ok};
use thiserror::Error;

#[allow(unused)]
use crate::WriteUpgradable;

#[allow(unused)]
use crate::stream::OffsetType;

#[allow(unused)]
use crate::stream::StdIoStream;
#[allow(unused)]
use crate::stream::with_source_locked;
use crate::{
    aesgcm::DynamicIvAes128Gcm,
    rng::fill_with_random,
    stream::{FileLike, LengthType, Stream, block::MultipleBlockReaderWriter},
};

pub const ID_SIZE: usize = 16;
pub const MAX_BLOCKS: u64 = (1u64 << 31) - 1;

pub trait LiteParamCalculator {
    fn compute_session_key(&self, salt: &[u8; ID_SIZE]) -> anyhow::Result<[u8; ID_SIZE]>;
    fn compute_padding(&self, salt: &[u8; ID_SIZE]) -> anyhow::Result<LengthType>;
    fn always_zero_padding(&self) -> bool {
        false
    }
}

use crate::stream::ambassador_impl_FileLike;

#[derive(Delegate)]
#[delegate(FileLike, target = "inner")]
pub struct LiteAesGcmCryptStream<S: Stream> {
    // The following are provided
    inner: S,
    iv_size: LengthType,
    block_size: LengthType,
    verify_mac: bool,

    // The following are computed
    padding_size: LengthType,
    aesgcm: DynamicIvAes128Gcm,
    aux: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum LiteAesGcmCryptError {
    #[error("invalid header for LiteAesGcmCryptStream")]
    InvalidHeader,
    #[error("too many blocks in the stream, exceeding the capabilities of AES-GCM")]
    TooManyBlocks,
    #[error("IV should not be zero")]
    NullIv,
    #[error("Tag mismatch indicating corrupted data")]
    TagMismatch,
    #[error("Written data only partially, causing corrupted data")]
    PartialWrite,
}

impl<S: Stream> LiteAesGcmCryptStream<S> {
    pub fn new(
        mut inner: S,
        lite_param_calc: &impl LiteParamCalculator,
        iv_size: LengthType,
        block_size: LengthType,
        verify_mac: bool,
    ) -> anyhow::Result<Self> {
        let mut id: [u8; ID_SIZE] = [0; ID_SIZE];
        let rc = inner.read(&mut id, 0)?;
        let mut aux: Vec<u8> = Vec::new();
        let padding_size: LengthType;
        if rc == 0 {
            fill_with_random(&mut id);
            inner.write(&id, 0)?;
            padding_size = lite_param_calc.compute_padding(&id)?;
            if padding_size > 0 {
                aux.resize(usize::try_from(padding_size)? + size_of::<u32>(), 0);
                fill_with_random(&mut aux[size_of::<u32>()..]);
            } else {
                aux.resize(size_of::<u32>(), 0);
            }
            inner.write(&aux, 0)?;
        } else if rc == id.len().try_into()? {
            padding_size = lite_param_calc.compute_padding(&id)?;
            aux.resize(usize::try_from(padding_size)? + size_of::<u32>(), 0);
            aux[..id.len()].copy_from_slice(&id);
            if padding_size > 0 && inner.read(&mut aux[size_of::<u32>()..], 0)? != padding_size {
                return Err(LiteAesGcmCryptError::InvalidHeader.into());
            }
        } else {
            return Err(LiteAesGcmCryptError::InvalidHeader.into());
        }
        let session_key_as_array = lite_param_calc.compute_session_key(&id)?;
        let key = Key::<Aes128Gcm>::from_slice(&session_key_as_array);
        let aesgcm = DynamicIvAes128Gcm::new(key);

        Ok(LiteAesGcmCryptStream {
            inner,
            iv_size,
            block_size,
            verify_mac,
            padding_size,
            aesgcm,
            aux,
        })
    }

    pub fn tag_size(&self) -> LengthType {
        16
    }

    pub fn iv_size(&self) -> LengthType {
        self.iv_size
    }

    pub fn padding_size(&self) -> LengthType {
        self.padding_size
    }

    pub fn header_size(&self) -> LengthType {
        ID_SIZE as LengthType + self.padding_size
    }

    pub fn underlying_block_size(&self) -> LengthType {
        self.block_size + self.iv_size + self.tag_size()
    }

    pub fn virtual_size_without_padding(
        underlying_size: LengthType,
        block_size: LengthType,
        iv_size: LengthType,
    ) -> LengthType {
        if underlying_size <= ID_SIZE as u64 {
            return 0;
        }
        let content_size = underlying_size - ID_SIZE as u64;
        let num_blocks = content_size / (block_size + iv_size + 16);
        let residue = content_size % (block_size + iv_size + 16);
        num_blocks * block_size + residue.saturating_sub(iv_size + 16)
    }

    pub fn max_physical_size_for_virtual_size(
        virtual_size: LengthType,
        block_size: LengthType,
        iv_size: LengthType,
        max_padding: LengthType,
    ) -> LengthType {
        max_padding
            + ID_SIZE as LengthType
            + virtual_size.div_ceil(block_size) * (block_size + iv_size + 16)
    }
}

impl<S: Stream> MultipleBlockReaderWriter for LiteAesGcmCryptStream<S> {
    fn block_size(&self) -> LengthType {
        self.block_size
    }

    fn read_multi_blocks(
        &mut self,
        buffer: &mut [u8],
        start_block_num: super::OffsetType,
        end_block_num: super::OffsetType,
    ) -> anyhow::Result<LengthType> {
        if end_block_num > MAX_BLOCKS {
            return Err(LiteAesGcmCryptError::TooManyBlocks)?;
        }
        let mut underlying_buffer: Vec<u8> =
            vec![0; ((end_block_num - start_block_num) * self.underlying_block_size()).try_into()?];
        let underlying_read_len = self.inner.read(
            &mut underlying_buffer,
            self.header_size() + start_block_num * self.underlying_block_size(),
        )?;
        let mut virtual_read_len: LengthType = 0;
        for i in (0..underlying_read_len).step_by(self.underlying_block_size().try_into()?) {
            let current_block: u32 =
                (i / self.underlying_block_size() + start_block_num).try_into()?;
            let this_block_underlying_size =
                self.underlying_block_size().min(underlying_read_len - i);
            if this_block_underlying_size <= self.iv_size() + self.tag_size() {
                break;
            }
            let this_block_virtual_size =
                this_block_underlying_size - self.iv_size() - self.tag_size();
            let this_underlying_buffer =
                &underlying_buffer[i.try_into()?..(i + this_block_underlying_size).try_into()?];
            let this_virtual_buffer = &mut buffer[virtual_read_len.try_into()?
                ..(virtual_read_len + this_block_virtual_size).try_into()?];
            if this_underlying_buffer.iter().all(|b: &u8| *b == 0) {
                this_virtual_buffer.fill(0);
            } else {
                let (iv, ciphertext) = this_underlying_buffer.split_at(self.iv_size().try_into()?);
                if iv.iter().all(|b| *b == 0) {
                    return Err(LiteAesGcmCryptError::NullIv)
                        .context(format!("reading data at block number {}", current_block));
                }
                let (ciphertext, tag) = ciphertext.split_at(this_block_virtual_size.try_into()?);
                self.aux[..size_of::<u32>()].copy_from_slice(&current_block.to_le_bytes());
                let success = self.aesgcm.decrypt(
                    iv,
                    &self.aux,
                    ciphertext,
                    tag.try_into()?,
                    this_virtual_buffer,
                )?;
                if !success && self.verify_mac {
                    return Err(LiteAesGcmCryptError::TagMismatch)
                        .context(format!("reading data at block number {}", current_block));
                }
            }

            virtual_read_len += this_block_virtual_size;
        }

        Ok(virtual_read_len)
    }

    fn write_multi_blocks(
        &mut self,
        buffer: &[u8],
        start_block_num: super::OffsetType,
        end_block_num: super::OffsetType,
        end_residue: super::OffsetType,
    ) -> anyhow::Result<()> {
        if end_block_num > MAX_BLOCKS {
            return Err(LiteAesGcmCryptError::TooManyBlocks)?;
        }
        let mut underlying_buffer: Vec<u8> = vec![
            0;
            ((end_block_num - start_block_num)
                * self.underlying_block_size()
                + if end_residue == 0 {
                    0
                } else {
                    end_residue + self.iv_size() + self.tag_size()
                })
            .try_into()?
        ];
        let mut virtual_write_len: LengthType = 0;
        for i in (0..underlying_buffer.len()).step_by(self.underlying_block_size().try_into()?) {
            let this_block_underlying_size = self
                .underlying_block_size()
                .min((underlying_buffer.len() - i).try_into()?);
            if this_block_underlying_size <= self.iv_size() + self.tag_size() {
                break;
            }
            let this_block_virtual_size =
                this_block_underlying_size - self.iv_size() - self.tag_size();
            let this_underlying_buffer =
                &mut underlying_buffer[i..i + usize::try_from(this_block_underlying_size)?];
            let (iv, ciphertext) = this_underlying_buffer.split_at_mut(self.iv_size().try_into()?);
            loop {
                fill_with_random(iv);
                if iv.iter().any(|b| *b != 0) {
                    break;
                }
            }
            let (ciphertext, tag) = ciphertext.split_at_mut(this_block_virtual_size.try_into()?);

            let this_virtual_buffer: &[u8] = &buffer[virtual_write_len.try_into()?
                ..(virtual_write_len + this_block_virtual_size).try_into()?];

            let current_block: u32 = (LengthType::try_from(i)? / self.underlying_block_size()
                + start_block_num)
                .try_into()?;
            self.aux[..size_of::<u32>()].copy_from_slice(&current_block.to_le_bytes());

            let computed_tag =
                self.aesgcm
                    .encrypt(iv, &self.aux, this_virtual_buffer, ciphertext)?;
            tag.copy_from_slice(computed_tag.as_slice());

            self.inner.write(
                this_underlying_buffer,
                self.header_size()
                    + start_block_num * self.underlying_block_size()
                    + LengthType::try_from(i)?,
            )?;
            virtual_write_len += this_block_virtual_size;
        }
        if virtual_write_len
            != ((end_block_num - start_block_num) * self.block_size() + end_residue).try_into()?
        {
            return Err(LiteAesGcmCryptError::PartialWrite)?;
        }
        Ok(())
    }

    fn adjust_logical_size(&mut self, length: LengthType) -> anyhow::Result<()> {
        let new_blocks = length / self.block_size();
        let residue = length % self.block_size();
        let new_size = self.header_size()
            + new_blocks * self.underlying_block_size()
            + if residue > 0 {
                residue + self.iv_size() + self.tag_size()
            } else {
                0
            };
        self.inner.resize(new_size)
    }

    fn size_mbrw(&self) -> anyhow::Result<LengthType> {
        let underlying_size = self.inner.size()?;
        if underlying_size <= self.header_size() {
            return Ok(0);
        }
        let content_size = underlying_size - self.header_size();
        let num_blocks = content_size / self.underlying_block_size();
        let residue = content_size % self.underlying_block_size();
        Ok(num_blocks * self.block_size()
            + residue.saturating_sub(self.iv_size() + self.tag_size()))
    }

    fn flush_mbrw(&mut self) -> anyhow::Result<()> {
        self.inner.flush()
    }

    fn lock_source_mrbw(&mut self) -> anyhow::Result<()> {
        self.inner.lock_source()
    }

    fn unlock_source_mrbw(&mut self) -> anyhow::Result<()> {
        self.inner.unlock_source()
    }
}

#[cfg(unix)]
pub mod unix {
    use std::os::fd::AsFd;
    use std::os::fd::AsRawFd;
    use std::os::fd::BorrowedFd;
    use std::os::fd::OwnedFd;

    use super::*;
    use crate::stream::ambassador_impl_Stream;

    #[derive(Delegate)]
    #[delegate(Stream, target = "inner")]
    pub struct LiteAesGcmOverFileStream {
        inner: LiteAesGcmCryptStream<StdIoStream>,
    }

    impl LiteAesGcmOverFileStream {
        pub fn new(mut inner: LiteAesGcmCryptStream<StdIoStream>) -> anyhow::Result<Self> {
            inner.lock_source()?;
            Ok(Self { inner })
        }
    }

    impl Drop for LiteAesGcmOverFileStream {
        fn drop(&mut self) {
            if let Err(err) = self.inner.unlock_source() {
                tracing::error!("failed to unlock file during destruction");
            }
        }
    }

    impl WriteUpgradable for LiteAesGcmOverFileStream {
        fn upgrade_to_writable(&mut self) -> anyhow::Result<()> {
            todo!()
        }
    }

    impl AsFd for LiteAesGcmOverFileStream {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.inner.inner.file.as_fd()
        }
    }

    #[cfg(target_os = "linux")]
    fn reopen_as_writable(fd: BorrowedFd<'_>) -> anyhow::Result<OwnedFd> {
        use rustix::fs::{Mode, OFlags};
        Ok(rustix::fs::open(
            format!("/proc/self/fd/{}", fd.as_raw_fd()),
            OFlags::RDWR,
            Mode::empty(),
        )?)
    }

    #[cfg(target_os = "macos")]
    fn reopen_as_writable(fd: BorrowedFd<'_>) -> anyhow::Result<OwnedFd> {
        use anyhow::Context;
        use rustix::fs::{Mode, OFlags};
        use std::ffi::CStr;

        let mut path_buffer = vec![0u8; (libc::PATH_MAX + 1) as usize];
        let ret = unsafe {
            libc::fcntl(
                fd.as_raw_fd(),
                libc::F_GETPATH,
                path_buffer.as_mut_ptr() as *mut libc::c_void,
            )
        };

        if ret < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("fcntl(F_GETPATH) failed for fd {}", fd.as_raw_fd()));
        }

        let path = unsafe { CStr::from_ptr(path_buffer.as_ptr() as *const libc::c_char) };
        Ok(rustix::fs::open(path, OFlags::RDWR, Mode::empty())?)
    }

    #[cfg(target_os = "freebsd")]
    fn reopen_as_writable(fd: BorrowedFd<'_>) -> anyhow::Result<OwnedFd> {
        use rustix::fs::{Mode, OFlags};

        let opath_fd = rustix::fs::openat(
            fd,
            c"",
            OFlags::from_bits_retain((libc::O_PATH | libc::O_EMPTY_PATH) as libc::c_uint),
            Mode::empty(),
        )?;
        Ok(rustix::fs::openat(
            opath_fd,
            c"",
            OFlags::from_bits_retain((libc::O_RDWR | libc::O_EMPTY_PATH) as libc::c_uint),
            Mode::empty(),
        )?)
    }

    #[cfg(test)]
    mod test {
        use std::{
            fs::File,
            io::{Read, Write},
        };

        use super::*;

        #[test]
        fn reopen() -> anyhow::Result<()> {
            let file = tempfile::NamedTempFile::new()?;
            file.as_file().write_all("Hello".as_bytes())?;

            let mut rofile = File::open(file.path())?;
            assert!(rofile.write_all("World".as_bytes()).is_err());

            let new_fd = reopen_as_writable(rofile.as_fd())?;
            let mut wfile = File::from(new_fd);

            let mut string = String::new();
            wfile.read_to_string(&mut string)?;
            assert_eq!(string, "Hello");

            wfile.write_all("World".as_bytes())?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use rstest::rstest;

    use crate::stream::{MemoryStream, test::compare_with_reference};

    use super::*;

    #[rstest]
    fn test_aes_gcm_stream(
        #[values(8, 12, 16)] iv_size: LengthType,
        #[values(127, 128)] block_size: LengthType,
        #[values(0, 8)] padding_size: LengthType,
    ) {
        struct ParamCalc {
            padding_size: LengthType,
        }

        impl LiteParamCalculator for ParamCalc {
            fn compute_session_key(&self, salt: &[u8; ID_SIZE]) -> anyhow::Result<[u8; ID_SIZE]> {
                let mut key = [0u8; ID_SIZE];
                for i in 0..ID_SIZE {
                    key[i] = salt[i] ^ 0xff;
                }
                Ok(key)
            }

            fn compute_padding(&self, _: &[u8; ID_SIZE]) -> anyhow::Result<LengthType> {
                Ok(self.padding_size)
            }

            fn always_zero_padding(&self) -> bool {
                self.padding_size == 0
            }
        }
        compare_with_reference(
            &mut LiteAesGcmCryptStream::new(
                MemoryStream { buffer: Vec::new() },
                &ParamCalc {
                    padding_size: padding_size,
                },
                iv_size,
                block_size,
                true,
            )
            .unwrap(),
            &mut MemoryStream { buffer: Vec::new() },
            1000,
        )
        .unwrap();
    }
}

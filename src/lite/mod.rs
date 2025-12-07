#[cfg(unix)]
use std::os::fd::{BorrowedFd, OwnedFd};

use aes_gcm::{
    KeyInit,
    aes::{Aes256, Block},
};
use anyhow::bail;
use ctr::cipher::BlockEncrypt;
use num_bigint::BigUint;

#[cfg(unix)]
use crate::stream::{StdIoStream, lite::LiteAesGcmCryptStream};
use crate::{
    MasterKeyType,
    protos::params::decrypted_securefs_params::Format_specific_params,
    stream::{Stream, lite::ID_SIZE},
};

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

#[cfg(unix)]
impl IoWrapperStream for LiteAesGcmCryptStream<StdIoStream> {
    fn as_fd(&self) -> std::os::unix::prelude::BorrowedFd<'_> {
        use std::os::fd::AsFd;

        unsafe { self.get_inner().as_ref().as_fd() }
    }

    fn replace_fd(&mut self, fd: std::os::unix::prelude::OwnedFd) {
        unsafe { self.replace_inner(StdIoStream::new(fd.into())) };
    }
}

pub struct LiteParamCalculator {
    content_enc: Aes256,
    padding_enc: Option<Aes256>,
    max_padding: u32,
}

impl LiteParamCalculator {
    pub fn new(
        content_key: MasterKeyType,
        padding_key: Option<MasterKeyType>,
        max_padding: u32,
    ) -> anyhow::Result<Self> {
        let content_enc = Aes256::new_from_slice(&content_key)?;
        let padding_enc = padding_key
            .as_ref()
            .map(|key| Aes256::new_from_slice(key))
            .transpose()?;
        Ok(Self {
            content_enc,
            padding_enc,
            max_padding,
        })
    }

    pub fn new_from_params(
        params: &crate::protos::params::DecryptedSecurefsParams,
    ) -> anyhow::Result<Self> {
        let Some(Format_specific_params::LiteFormatParams(ref lite)) =
            params.format_specific_params
        else {
            bail!("Not a lite params");
        };
        let padding_key: Option<MasterKeyType> = if lite.padding_key.iter().any(|i| *i != 0) {
            Some(lite.padding_key.as_slice().try_into()?)
        } else {
            None
        };
        Self::new(
            lite.content_key.as_slice().try_into()?,
            padding_key,
            params.size_params.max_padding_size,
        )
    }
}

impl crate::stream::lite::LiteParamCalculator for LiteParamCalculator {
    fn compute_session_key(
        &self,
        salt: &[u8; crate::stream::lite::ID_SIZE],
    ) -> anyhow::Result<[u8; crate::stream::lite::ID_SIZE]> {
        let mut out_block: Block = [0u8; ID_SIZE].into();
        self.content_enc
            .encrypt_block_b2b(salt.into(), &mut out_block);
        Ok(out_block.into())
    }

    fn compute_padding(
        &self,
        salt: &[u8; crate::stream::lite::ID_SIZE],
    ) -> anyhow::Result<crate::stream::LengthType> {
        if self.always_zero_padding() {
            return Ok(0);
        }
        let Some(padding_enc) = &self.padding_enc else {
            bail!("padding enc is null even though max padding is nonzero");
        };
        let mut out_block: Block = [0u8; ID_SIZE].into();
        padding_enc.encrypt_block_b2b(salt.into(), &mut out_block);
        Ok((BigUint::from_bytes_be(&out_block) % (self.max_padding + 1)).try_into()?)
    }

    fn always_zero_padding(&self) -> bool {
        self.max_padding == 0
    }
}

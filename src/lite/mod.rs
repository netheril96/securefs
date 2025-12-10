#[cfg(unix)]
use std::os::fd::AsFd;

use aes_gcm::{
    KeyInit,
    aes::{Aes256, Block},
};

use anyhow::bail;
use ctr::cipher::BlockEncrypt;
use num_bigint::BigUint;

#[allow(unused)]
use crate::stream::StdIoStream;

#[allow(unused)]
use crate::WriteUpgradable;

use crate::{
    MasterKeyType, OwnedFileDescriptor,
    protos::params::decrypted_securefs_params::Format_specific_params,
    stream::{
        MemoryStream, Stream,
        lite::{ID_SIZE, LiteAesGcmCryptStream},
    },
};

pub mod fuse;
pub mod long_name_db;

pub mod name_translators;
pub mod unix;

#[cfg(unix)]
pub trait IoWrapperStream: Stream + WriteUpgradable + AsFd {}

#[cfg(unix)]
impl<T: Stream + WriteUpgradable + AsFd> IoWrapperStream for T {}

#[cfg(unix)]
pub trait IoWrapperFactory {
    fn compute_virtual_size(&self, underlying_size: u64) -> Option<u64>;
    fn wrap(&self, fd: OwnedFileDescriptor) -> anyhow::Result<Box<dyn IoWrapperStream>>;
}

pub struct LiteAesGcmCryptStreamFactory {
    size_params: crate::protos::params::decrypted_securefs_params::SizeParams,
    lite_param_calc: LiteParamCalculator,
    verify_mac: bool,
}

impl LiteAesGcmCryptStreamFactory {
    pub fn new(
        size_params: crate::protos::params::decrypted_securefs_params::SizeParams,
        lite_param_calc: LiteParamCalculator,
        verify_mac: bool,
    ) -> Self {
        Self {
            size_params,
            lite_param_calc,
            verify_mac,
        }
    }

    pub fn new_from_params(
        params: &crate::protos::params::DecryptedSecurefsParams,
        verify_mac: bool,
    ) -> anyhow::Result<Self> {
        Ok(Self::new(
            params
                .size_params
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("no size params available"))?
                .clone(),
            LiteParamCalculator::new_from_params(params)?,
            verify_mac,
        ))
    }

    fn generic_wrap<Inner>(
        &self,
        fd: OwnedFileDescriptor,
    ) -> anyhow::Result<LiteAesGcmCryptStream<Inner>>
    where
        Inner: From<OwnedFileDescriptor> + Stream,
    {
        LiteAesGcmCryptStream::new(
            Inner::from(fd),
            &self.lite_param_calc,
            self.size_params.iv_size.into(),
            self.size_params.block_size.into(),
            true,
        )
    }

    fn compute_virtual_size(&self, underlying_size: u64) -> Option<u64> {
        if self.size_params.max_padding_size > 0 {
            None
        } else {
            Some(
                // This method is the same for all inner streams.
                LiteAesGcmCryptStream::<MemoryStream>::virtual_size_without_padding(
                    underlying_size,
                    self.size_params.block_size.into(),
                    self.size_params.iv_size.into(),
                ),
            )
        }
    }
}

#[cfg(unix)]
impl IoWrapperFactory for LiteAesGcmCryptStreamFactory {
    fn compute_virtual_size(&self, underlying_size: u64) -> Option<u64> {
        self.compute_virtual_size(underlying_size)
    }

    fn wrap(&self, fd: OwnedFileDescriptor) -> anyhow::Result<Box<dyn IoWrapperStream>> {
        self.generic_wrap::<StdIoStream>(fd).map(|x| {
            use crate::stream::lite::unix::LiteAesGcmOverFileStream;

            let y: Box<dyn IoWrapperStream> = Box::new(LiteAesGcmOverFileStream::new(x));
            y
        })
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

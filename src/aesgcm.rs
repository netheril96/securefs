#![allow(unused)]

use aes_gcm::{
    Key, KeyInit, Tag,
    aead::{Error, consts::U16},
    aes::{
        Aes128, Aes256,
        cipher::{BlockCipher, BlockEncrypt, StreamCipher},
    },
};
use ctr::Ctr32BE;
use ctr::{
    CtrCore,
    cipher::{InnerIvInit, StreamCipherCore, StreamCipherError},
};
use ghash::GHash;
use ghash::universal_hash::UniversalHash;
use subtle::ConstantTimeEq;

type Block = ghash::Block;

/// An implementation of AES-GCM that supports dynamic IV sizes.
/// It is generic over the AES implementation.
pub struct DynamicIvAesGcm<Aes> {
    cipher: Aes,
    ghash: GHash,
}

impl<Aes> DynamicIvAesGcm<Aes>
where
    Aes: BlockCipher<BlockSize = U16> + BlockEncrypt + Clone,
{
    /// Creates a new `DynamicIvAesGcm` instance from an AES key.
    pub fn new(key: &Key<Aes>) -> Self
    where
        Aes: KeyInit,
    {
        let cipher = Aes::new(key);
        let mut ghash_key = ghash::Key::default();
        cipher.encrypt_block(&mut ghash_key);
        let ghash = GHash::new(&ghash_key);
        Self { cipher, ghash }
    }

    fn init_ctr(&self, nonce: &[u8]) -> (Ctr32BE<&Aes>, Block) {
        let j0 = if nonce.len() == 12 {
            let mut block = Block::default();
            block[..12].copy_from_slice(nonce);
            block[15] = 1;
            block
        } else {
            let mut ghash = self.ghash.clone();
            ghash.update_padded(nonce);

            let mut block = Block::default();
            let nonce_bits = (nonce.len() as u64) * 8;
            block[8..].copy_from_slice(&nonce_bits.to_be_bytes());
            ghash.update(&[block]);
            ghash.finalize()
        };
        let mut core = CtrCore::<&Aes, ctr::flavors::Ctr32BE>::inner_iv_init(&self.cipher, &j0);
        let mut tag_mask = Block::default();
        core.write_keystream_block(&mut tag_mask);
        let ctr = Ctr32BE::<&Aes>::from_core(core);
        (ctr, tag_mask)
    }

    fn compute_tag(&self, mask: Block, associated_data: &[u8], buffer: &[u8]) -> Tag {
        let mut ghash = self.ghash.clone();
        ghash.update_padded(associated_data);
        ghash.update_padded(buffer);

        let associated_data_bits = (associated_data.len() as u64) * 8;
        let buffer_bits = (buffer.len() as u64) * 8;

        let mut block = Block::default();
        block[..8].copy_from_slice(&associated_data_bits.to_be_bytes());
        block[8..].copy_from_slice(&buffer_bits.to_be_bytes());
        ghash.update(&[block]);

        let mut tag = ghash.finalize();
        for (a, b) in tag.as_mut_slice().iter_mut().zip(mask.as_slice()) {
            *a ^= *b;
        }
        tag
    }

    /// Encrypts the given buffer in place and returns the authentication tag.
    pub fn encrypt_in_place_detached(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        let (mut ctr, mask) = self.init_ctr(nonce);
        ctr.apply_keystream(buffer);
        Ok(self.compute_tag(mask, associated_data, buffer))
    }

    /// Decrypts the given buffer in place, verifying the authentication tag.
    pub fn decrypt_in_place_detached(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        let (mut ctr, mask) = self.init_ctr(nonce);
        let expected_tag = self.compute_tag(mask, associated_data, buffer);

        if expected_tag.ct_eq(tag).into() {
            ctr.apply_keystream(buffer);
            Ok(())
        } else {
            Err(Error)
        }
    }
}

impl<Aes> DynamicIvAesGcm<Aes>
where
    Aes: BlockCipher<BlockSize = U16> + BlockEncrypt + Clone,
{
    /// Encrypts the given plaintext.
    pub fn encrypt(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<Tag, StreamCipherError> {
        let (mut ctr, mask) = self.init_ctr(nonce);
        ctr.apply_keystream_b2b(plaintext, ciphertext)?;
        let tag = self.compute_tag(mask, associated_data, ciphertext);
        Ok(tag)
    }

    /// Decrypts the given ciphertext.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        ciphertext: &[u8],
        tag: &Tag,
        plaintext: &mut [u8],
    ) -> Result<bool, StreamCipherError> {
        let (mut ctr, mask) = self.init_ctr(nonce);
        let expected_tag = self.compute_tag(mask, associated_data, ciphertext);
        if expected_tag.ct_eq(tag).into() {
            ctr.apply_keystream_b2b(ciphertext, plaintext)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Encrypts the given plaintext.
    pub fn encrypt_alloc(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Tag), StreamCipherError> {
        let mut ciphertext = vec![0u8; plaintext.len()];
        let tag = self.encrypt(nonce, associated_data, plaintext, &mut ciphertext)?;
        Ok((ciphertext, tag))
    }

    /// Decrypts the given ciphertext.
    pub fn decrypt_alloc(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        ciphertext: &[u8],
        tag: &Tag,
    ) -> Result<(Vec<u8>, bool), StreamCipherError> {
        let mut plaintext: Vec<u8> = vec![0u8; ciphertext.len()];
        let success = self.decrypt(nonce, associated_data, ciphertext, tag, &mut plaintext)?;
        Ok((plaintext, success))
    }
}

pub type DynamicIvAes128Gcm = DynamicIvAesGcm<Aes128>;
pub type DynamicIvAes256Gcm = DynamicIvAesGcm<Aes256>;

#[cfg(test)]
mod test {

    use std::error::Error;

    use super::*;

    struct ReferenceData {
        plaintext: &'static [u8],
        ciphertext: &'static [u8],
        tag: &'static [u8],
        associated_data: &'static [u8],
        key: &'static [u8],
        nonce: &'static [u8],
    }

    impl ReferenceData {
        fn run_test_internal<Aes>(&self) -> Result<(), StreamCipherError>
        where
            Aes: BlockCipher<BlockSize = U16> + BlockEncrypt + KeyInit + Clone,
        {
            let key = Key::<Aes>::from_slice(self.key);
            let cipher = DynamicIvAesGcm::<Aes>::new(&key);
            let (ciphertext, tag) =
                cipher.encrypt_alloc(self.nonce, self.associated_data, self.plaintext)?;
            let (plaintext, success) =
                cipher.decrypt_alloc(self.nonce, self.associated_data, &ciphertext, &tag)?;
            assert!(success);
            assert_eq!(plaintext, self.plaintext);
            assert_eq!(ciphertext, self.ciphertext);
            assert_eq!(tag.as_slice(), self.tag);
            Ok(())
        }

        fn run_test(&self) {
            match self.key.len() {
                16 => self.run_test_internal::<Aes128>().unwrap(),
                32 => self.run_test_internal::<Aes256>().unwrap(),
                _ => panic!("Invalid key length"),
            }
        }
    }

    #[test]
    fn test_key256_iv96() {
        // Generated Rust Reference Data for Cryptographic Testing
        // Note: ciphertext and tag were generated via AES-GCM encryption.
        // Unique ID ensures multiple test vectors can be used in the same project.

        /// Static test data for key (Test ID: D79CB997). Size: 32 bytes
        const RUST_KEY_DATA: &'static [u8] = &[
            0xd7, 0x10, 0xe9, 0xd3, 0x93, 0x63, 0x22, 0x87, 0x4c, 0x7f, 0x8e, 0xf3, 0xd1, 0xe6,
            0x85, 0x6b, 0x13, 0x92, 0x75, 0x4e, 0x06, 0x0c, 0x0e, 0x63, 0x8f, 0x19, 0x41, 0x5d,
            0xa9, 0xe5, 0xda, 0x2f,
        ];

        /// Static test data for nonce (Test ID: D79CB997). Size: 12 bytes
        const RUST_NONCE_DATA: &'static [u8] = &[
            0x9f, 0x20, 0x0a, 0x9d, 0x94, 0xcc, 0x8f, 0x51, 0x95, 0xa1, 0xd3, 0x72,
        ];

        /// Static test data for plaintext (Test ID: D79CB997). Size: 64 bytes
        const RUST_PLAINTEXT_DATA: &'static [u8] = &[
            0x5c, 0xc0, 0xa1, 0x91, 0x67, 0x83, 0x22, 0x4e, 0xab, 0x57, 0x06, 0x32, 0x26, 0xce,
            0x70, 0x42, 0x12, 0x30, 0x20, 0xaa, 0xfe, 0xf1, 0xe4, 0x4b, 0x67, 0xed, 0x5b, 0xee,
            0x52, 0x51, 0x6a, 0x4d, 0x1a, 0xbb, 0x31, 0x8f, 0x38, 0x74, 0xf3, 0xd4, 0x0a, 0xa9,
            0xc3, 0xba, 0x7c, 0x54, 0x66, 0xc4, 0xae, 0x40, 0x37, 0x52, 0xae, 0x2e, 0x11, 0x08,
            0xf1, 0xb4, 0x5b, 0x52, 0xbb, 0x6e, 0x0f, 0x68,
        ];

        /// Static test data for associated_data (Test ID: D79CB997). Size: 32
        /// bytes
        const RUST_ASSOCIATED_DATA_DATA: &'static [u8] = &[
            0x61, 0x57, 0x9c, 0xbb, 0xcb, 0xc9, 0xc6, 0x85, 0x12, 0xa4, 0x15, 0x15, 0x05, 0xc4,
            0x2f, 0x73, 0xbc, 0xdb, 0xb9, 0x0e, 0x5e, 0xc8, 0x27, 0xf8, 0x01, 0xa9, 0x43, 0xde,
            0xae, 0x7c, 0x07, 0x00,
        ];

        /// Static test data for ciphertext (Test ID: D79CB997). Size: 64 bytes
        const RUST_CIPHERTEXT_DATA: &'static [u8] = &[
            0x67, 0xae, 0xac, 0x26, 0x94, 0xea, 0xe9, 0x74, 0x0d, 0x48, 0xb0, 0xba, 0x9b, 0x56,
            0xaf, 0x2c, 0x84, 0x48, 0x75, 0x98, 0x4d, 0x01, 0x1b, 0xec, 0x40, 0xb0, 0x3d, 0x2c,
            0x52, 0x2c, 0xad, 0x85, 0x5d, 0x96, 0x89, 0xf1, 0x84, 0x78, 0x53, 0xe3, 0xf2, 0xf4,
            0x71, 0xe5, 0xff, 0x58, 0x46, 0x93, 0x6d, 0x74, 0x36, 0xbd, 0x3c, 0xb1, 0xd0, 0x9c,
            0xba, 0x33, 0x8b, 0x94, 0x22, 0x4f, 0x6d, 0xdc,
        ];

        /// Static test data for tag (Test ID: D79CB997). Size: 16 bytes
        const RUST_TAG_DATA: &'static [u8] = &[
            0xe6, 0x4d, 0x38, 0xb6, 0xc4, 0x79, 0x40, 0x77, 0xe3, 0x9c, 0x24, 0x90, 0x71, 0x38,
            0xd6, 0xca,
        ];

        /// --- ReferenceData Initialization (Unique ID: D79CB997) ---
        /// Assumes 'pub struct ReferenceData' is already defined in scope.
        const TEST_REFERENCE_DATA: ReferenceData = ReferenceData {
            plaintext: RUST_PLAINTEXT_DATA,
            ciphertext: RUST_CIPHERTEXT_DATA,
            tag: RUST_TAG_DATA,
            associated_data: RUST_ASSOCIATED_DATA_DATA,
            key: RUST_KEY_DATA,
            nonce: RUST_NONCE_DATA,
        };

        TEST_REFERENCE_DATA.run_test();
    }

    #[test]
    fn test_key128_iv88() {
        // Generated Rust Reference Data for Cryptographic Testing
        // Note: ciphertext and tag were generated via AES-GCM encryption.
        // Unique ID ensures multiple test vectors can be used in the same project.

        /// Static test data for key Size: 16 bytes
        const RUST_KEY_DATA: &'static [u8] = &[
            0x41, 0x63, 0x11, 0xd1, 0x00, 0x5e, 0x5f, 0xe5, 0x88, 0xa0, 0x41, 0xf5, 0xfd, 0x80,
            0xb6, 0x27,
        ];

        /// Static test data for nonce Size: 11 bytes
        const RUST_NONCE_DATA: &'static [u8] = &[
            0x45, 0xc1, 0x1b, 0x73, 0xa3, 0xfa, 0x4b, 0xfb, 0xff, 0xa4, 0x5b,
        ];

        /// Static test data for plaintext Size: 7 bytes
        const RUST_PLAINTEXT_DATA: &'static [u8] = &[0xdf, 0x91, 0xd5, 0x1d, 0x96, 0x95, 0x45];

        /// Static test data for associated_data Size: 0 bytes
        const RUST_ASSOCIATED_DATA_DATA: &'static [u8] = &[];

        /// Static test data for ciphertext Size: 7 bytes
        const RUST_CIPHERTEXT_DATA: &'static [u8] = &[0x5f, 0xdc, 0x15, 0xa8, 0xf8, 0x1d, 0x62];

        /// Static test data for tag Size: 16 bytes
        const RUST_TAG_DATA: &'static [u8] = &[
            0x76, 0x59, 0x2e, 0x30, 0x6d, 0xb2, 0xae, 0x69, 0x2e, 0x7f, 0x64, 0x77, 0x50, 0x24,
            0x3d, 0xe2,
        ];

        /// --- ReferenceData Initialization ---
        /// Assumes 'pub struct ReferenceData' is already defined in scope.
        pub const TEST_REFERENCE_DATA: ReferenceData = ReferenceData {
            plaintext: RUST_PLAINTEXT_DATA,
            ciphertext: RUST_CIPHERTEXT_DATA,
            tag: RUST_TAG_DATA,
            associated_data: RUST_ASSOCIATED_DATA_DATA,
            key: RUST_KEY_DATA,
            nonce: RUST_NONCE_DATA,
        };

        TEST_REFERENCE_DATA.run_test();
    }

    #[test]
    fn test_key128_iv256() {
        // Generated Rust Reference Data for Cryptographic Testing
        // Note: ciphertext and tag were generated via AES-GCM encryption.
        // Unique ID ensures multiple test vectors can be used in the same project.

        /// Static test data for key Size: 16 bytes
        const RUST_KEY_DATA: &'static [u8] = &[
            0x9a, 0x23, 0x76, 0x46, 0x78, 0xf0, 0xf8, 0xb0, 0xbd, 0x35, 0x3f, 0x56, 0x24, 0x96,
            0xbb, 0xb7,
        ];

        /// Static test data for nonce Size: 32 bytes
        const RUST_NONCE_DATA: &'static [u8] = &[
            0x1a, 0xf6, 0x9b, 0x54, 0xcb, 0xae, 0x73, 0x15, 0xd2, 0x39, 0x78, 0x9e, 0x41, 0xad,
            0x20, 0x6e, 0x2a, 0x5b, 0x1f, 0xd9, 0x25, 0x2b, 0x17, 0xb2, 0x0a, 0xc2, 0x76, 0x38,
            0x7f, 0x73, 0x80, 0x55,
        ];

        /// Static test data for plaintext Size: 64 bytes
        const RUST_PLAINTEXT_DATA: &'static [u8] = &[
            0xeb, 0x8f, 0xd2, 0xbd, 0x97, 0x28, 0xc3, 0x32, 0x10, 0xb9, 0xda, 0x2c, 0x06, 0xe2,
            0x8a, 0x46, 0xcc, 0xc3, 0x52, 0x16, 0x92, 0x4c, 0x15, 0xbc, 0x73, 0x95, 0xec, 0xce,
            0x3d, 0x0a, 0xa4, 0x3d, 0x9a, 0xfe, 0x3a, 0xe7, 0xb0, 0x7e, 0xd6, 0x77, 0xf9, 0xcf,
            0x5d, 0x09, 0x18, 0xf3, 0x12, 0x0b, 0x22, 0x02, 0x00, 0xf1, 0xed, 0x70, 0xd7, 0x81,
            0x63, 0x60, 0xe4, 0x3c, 0x3c, 0x4d, 0x1c, 0x78,
        ];

        /// Static test data for associated_data Size: 5 bytes
        const RUST_ASSOCIATED_DATA_DATA: &'static [u8] = &[0x4d, 0xf9, 0xdb, 0xbf, 0x34];

        /// Static test data for ciphertext Size: 64 bytes
        const RUST_CIPHERTEXT_DATA: &'static [u8] = &[
            0xd0, 0xdf, 0x6a, 0xd2, 0x4f, 0x39, 0xc7, 0xd8, 0xbb, 0x0e, 0x95, 0xb5, 0xc0, 0xf6,
            0xab, 0x72, 0x87, 0xf7, 0x0d, 0x19, 0x7c, 0xe4, 0x18, 0x76, 0x14, 0x04, 0xdc, 0x20,
            0xa1, 0x67, 0x3f, 0x30, 0x52, 0x09, 0x5b, 0xd4, 0xe7, 0x9e, 0x7e, 0xf0, 0x9e, 0x2f,
            0x3b, 0xaf, 0x5d, 0x6f, 0x08, 0xcc, 0x5b, 0x65, 0x67, 0x83, 0xb9, 0x13, 0xa7, 0xa7,
            0xd2, 0x7a, 0xca, 0xfe, 0xae, 0x38, 0xb7, 0xe9,
        ];

        /// Static test data for tag Size: 16 bytes
        const RUST_TAG_DATA: &'static [u8] = &[
            0x0d, 0x89, 0xe4, 0x89, 0x48, 0xfd, 0x59, 0x8c, 0xec, 0x7d, 0xb0, 0x07, 0xb2, 0x77,
            0x52, 0xf2,
        ];

        /// --- ReferenceData Initialization ---
        /// Assumes 'pub struct ReferenceData' is already defined in scope.
        pub const TEST_REFERENCE_DATA: ReferenceData = ReferenceData {
            plaintext: RUST_PLAINTEXT_DATA,
            ciphertext: RUST_CIPHERTEXT_DATA,
            tag: RUST_TAG_DATA,
            associated_data: RUST_ASSOCIATED_DATA_DATA,
            key: RUST_KEY_DATA,
            nonce: RUST_NONCE_DATA,
        };

        TEST_REFERENCE_DATA.run_test();
    }
}

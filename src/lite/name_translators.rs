use std::{cell::RefCell, ops::DerefMut};

use aes_gcm::KeyInit;
use aes_siv::siv::Aes128Siv;
use thiserror::Error;

use crate::MasterKeyType;

const ENC_DUDE: &'static [u8; 32] = b"ABCDEFGHIJKMNPQRSTUVWXYZ23456789";
fast32::make_base32_alpha!(
    DUDE,
    DEC_DUDE,
    ENC_DUDE,
    b"abcdefghijklmnpqrstvwxyz",
    b"ABCDEFGHIJKIMNPQRSTVWXYZ"
);

pub fn encrypt_filename_component(name: &[u8], aes_siv: &mut Aes128Siv) -> anyhow::Result<Vec<u8>> {
    if name.is_empty() {
        return Ok(Vec::new());
    }
    let empty_header: [[u8; 0]; 0] = [];
    let enc = aes_siv.encrypt(&empty_header, name)?;
    Ok(DUDE.encode(&enc).into_bytes())
}

pub fn decrypt_filename_component(name: &[u8], aes_siv: &mut Aes128Siv) -> Option<Vec<u8>> {
    if name.is_empty() {
        return Some(Vec::new());
    }
    let bytes = DUDE.decode(name).ok()?;
    let empty_header: [[u8; 0]; 0] = [];
    aes_siv.decrypt(&empty_header, &bytes).ok()
}

#[derive(Debug, PartialEq, Eq)]
pub enum NameDecodeOutput {
    InvalidName,
    LongName,
    Decoded(Vec<u8>),
}

pub trait NameTranslator {
    fn is_no_op(&self) -> bool {
        false
    }
    fn encode_name(&self, name: &[u8]) -> anyhow::Result<Vec<u8>>;
    fn decode_name(&self, name: &[u8]) -> NameDecodeOutput;
    fn encode_path_for_symlink(&self, path: &[u8]) -> anyhow::Result<Vec<u8>>;
    fn decode_path_for_symlink(&self, path: &[u8]) -> anyhow::Result<Vec<u8>>;
    fn max_virtual_path_component_size(&self, physical_size: u32) -> u32;
}

pub struct NoOpNameTranslator {}

impl NameTranslator for NoOpNameTranslator {
    fn encode_name(&self, name: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(name.into())
    }

    fn decode_name(&self, name: &[u8]) -> NameDecodeOutput {
        NameDecodeOutput::Decoded(name.into())
    }

    fn encode_path_for_symlink(&self, path: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(path.into())
    }

    fn decode_path_for_symlink(&self, path: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(path.into())
    }

    fn max_virtual_path_component_size(&self, physical_size: u32) -> u32 {
        physical_size
    }
}

pub struct LegacyNameTranslator {
    master_key: MasterKeyType,
    aes_siv: thread_local::ThreadLocal<RefCell<Aes128Siv>>,
}

impl LegacyNameTranslator {
    pub fn new(master_key: MasterKeyType) -> Self {
        Self {
            master_key,
            aes_siv: thread_local::ThreadLocal::new(),
        }
    }

    fn get_aes_siv(&self) -> &RefCell<Aes128Siv> {
        self.aes_siv.get_or(|| {
            let aes_siv = Aes128Siv::new_from_slice(&self.master_key)
                .expect("AES-SIV initialization shouldn't fail");
            RefCell::new(aes_siv)
        })
    }
}

#[derive(Debug, Error)]
pub enum NameError {
    #[error("Not a previously encrypted name: {name}")]
    NotPreviousEncodedName { name: String },
}

impl NameTranslator for LegacyNameTranslator {
    fn encode_name(&self, name: &[u8]) -> anyhow::Result<Vec<u8>> {
        encrypt_filename_component(name, self.get_aes_siv().borrow_mut().deref_mut())
    }

    fn decode_name(&self, name: &[u8]) -> NameDecodeOutput {
        match decrypt_filename_component(name, self.get_aes_siv().borrow_mut().deref_mut()) {
            Some(decoded) => NameDecodeOutput::Decoded(decoded),
            None => NameDecodeOutput::InvalidName,
        }
    }

    fn encode_path_for_symlink(&self, path: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut result: Vec<u8> = Vec::new();
        for part in path.split(|&x| x == std::path::MAIN_SEPARATOR as u8) {
            result.extend_from_slice(&self.encode_name(part)?);
            result.push(std::path::MAIN_SEPARATOR as u8);
        }
        result.pop();
        Ok(result)
    }

    fn decode_path_for_symlink(&self, path: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut result: Vec<u8> = Vec::new();
        for part in path.split(|&x| x == std::path::MAIN_SEPARATOR as u8) {
            match self.decode_name(part) {
                NameDecodeOutput::InvalidName | NameDecodeOutput::LongName => {
                    return Err(NameError::NotPreviousEncodedName {
                        name: String::from_utf8_lossy(part).into_owned(),
                    })?;
                }
                NameDecodeOutput::Decoded(items) => {
                    result.extend_from_slice(&items);
                    result.push(std::path::MAIN_SEPARATOR as u8);
                }
            }
        }
        result.pop();
        Ok(result)
    }

    fn max_virtual_path_component_size(&self, physical_size: u32) -> u32 {
        (physical_size * 5 / 8).saturating_sub(16)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    struct NameTranscodingReference {
        encoded: &'static str,
        decoded: &'static str,
    }

    impl NameTranscodingReference {
        fn test_name_component(&self, trans: &dyn NameTranslator) {
            assert_eq!(
                str::from_utf8(&trans.encode_name(self.decoded.as_bytes()).unwrap()).unwrap(),
                self.encoded
            );
            match trans.decode_name(self.encoded.as_bytes()) {
                NameDecodeOutput::Decoded(bytes) => {
                    assert_eq!(str::from_utf8(bytes.as_slice()).unwrap(), self.decoded)
                }
                _ => panic!("Should decode fine"),
            }
        }

        fn test_symlink(&self, trans: &dyn NameTranslator) {
            assert_eq!(
                str::from_utf8(
                    &trans
                        .encode_path_for_symlink(self.decoded.as_bytes())
                        .unwrap()
                )
                .unwrap(),
                self.encoded
            );
            assert_eq!(
                str::from_utf8(
                    &trans
                        .decode_path_for_symlink(self.encoded.as_bytes())
                        .unwrap()
                )
                .unwrap(),
                self.decoded
            );
        }
    }

    #[test]
    fn test_legacy_name_translator() {
        let nt = LegacyNameTranslator::new([255u8; 32]);
        NameTranscodingReference {
            encoded: "ZFEHY3W9JM8QRR4GBJ67JRY3KENMEKX2GA",
            decoded: "abCDe",
        }
        .test_name_component(&nt);
        NameTranscodingReference {
            encoded: "DX8MQEKK8ENI3UUE2J3Q76R5K9RS9JS",
            decoded: "666",
        }
        .test_name_component(&nt);
        NameTranscodingReference {
            encoded: "AJRCK9GN87E3XDNGWKY48F6MEG752",
            decoded: "ß",
        }
        .test_name_component(&nt);
        NameTranscodingReference {
            encoded: "C5SRCFXE5DS89E45EP6YHSAWW54TRGCHUVKVX3N8YY7A7NE6M99TDDSPF6RN7ANRUYXKVRY9D8CP5GQKMCZETWQC",
            decoded: "Be human readable and machine readable.",
        }
        .test_name_component(&nt);
        NameTranscodingReference {
            encoded: "/ZFEHY3W9JM8QRR4GBJ67JRY3KENMEKX2GA/DX8MQEKK8ENI3UUE2J3Q76R5K9RS9JS",
            decoded: "/abCDe/666",
        }
        .test_symlink(&nt);
    }

    #[test]
    fn test_siv_rfc() {
        // Test vector from RFC 5297
        let key: [u8; 32] = [
            0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2,
            0xf1, 0xf0, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
            0xfc, 0xfd, 0xfe, 0xff,
        ];
        let ad: &[&[u8]] = &[&[
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        ]];
        let plaintext: &[u8] = &[
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        ];
        let expected_siv: [u8; 16] = [
            0x85, 0x63, 0x2d, 0x07, 0xc6, 0xe8, 0xf3, 0x7f, 0x95, 0x0a, 0xcd, 0x32, 0x0a, 0x2e,
            0xcc, 0x93,
        ];
        let expected_ciphertext: &[u8] = &[
            0x40, 0xc0, 0x2b, 0x96, 0x90, 0xc4, 0xdc, 0x04, 0xda, 0xef, 0x7f, 0x6a, 0xfe, 0x5c,
        ];

        let mut aes_siv =
            Aes128Siv::new_from_slice(&key).expect("AES-SIV initialization shouldn't fail");

        // Test encryption
        let output = aes_siv.encrypt(ad, plaintext).unwrap();
        let (siv, ciphertext) = output.split_at(16);

        assert_eq!(siv, &expected_siv);
        assert_eq!(ciphertext, expected_ciphertext);

        // Test decryption
        let decrypted_plaintext = aes_siv.decrypt(ad, &output).unwrap();
        assert_eq!(decrypted_plaintext, plaintext);
    }

    #[test]
    fn test_siv_null_ad() {
        let key: [u8; 32] = [
            62, 186, 247, 236, 192, 108, 233, 1, 35, 104, 164, 67, 49, 22, 141, 96, 58, 166, 74,
            198, 110, 11, 33, 103, 74, 152, 59, 7, 171, 33, 136, 196,
        ];
        let ad: &[&[u8]] = &[];
        let plaintext: &[u8] = &[
            84, 104, 105, 115, 32, 105, 115, 32, 116, 104, 101, 32, 115, 101, 99, 114, 101, 116,
            32, 109, 101, 115, 115, 97, 103, 101, 32, 116, 104, 97, 116, 32, 110, 101, 101, 100,
            115, 32, 116, 111, 32, 98, 101, 32, 101, 110, 99, 114, 121, 112, 116, 101, 100, 32,
            100, 101, 116, 101, 114, 109, 105, 110, 105, 115, 116, 105, 99, 97, 108, 108, 121, 46,
        ];
        let expected_siv: [u8; 16] = [
            46, 3, 26, 59, 15, 63, 85, 232, 216, 167, 245, 229, 85, 29, 245, 71,
        ];
        let expected_ciphertext: &[u8] = &[
            71, 147, 240, 64, 136, 240, 69, 4, 64, 142, 56, 142, 163, 53, 152, 221, 15, 100, 8,
            224, 186, 173, 93, 15, 24, 22, 194, 15, 230, 153, 135, 43, 16, 91, 2, 220, 232, 157,
            124, 97, 130, 224, 236, 251, 68, 167, 218, 85, 62, 244, 12, 9, 198, 154, 199, 85, 189,
            69, 31, 240, 196, 18, 60, 167, 239, 59, 244, 214, 98, 75, 6, 179,
        ];

        let mut aes_siv =
            Aes128Siv::new_from_slice(&key).expect("AES-SIV initialization shouldn't fail");

        // Test encryption
        let output = aes_siv.encrypt(ad, plaintext).unwrap();
        let (siv, ciphertext) = output.split_at(16);

        assert_eq!(siv, &expected_siv);
        assert_eq!(ciphertext, expected_ciphertext);

        // Test decryption
        let decrypted_plaintext = aes_siv.decrypt(ad, &output).unwrap();
        assert_eq!(decrypted_plaintext, plaintext);
    }
}

use anyhow::{Context, Result, bail};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use protobuf::Message;
use sha2::Sha256;
use std::borrow::Cow;
use thiserror::Error;

use crate::rng::fill_with_random;
use crate::stream::Stream;
use crate::{
    aesgcm::DynamicIvAes256Gcm,
    protos::params::{
        DecryptedSecurefsParams, EncryptedSecurefsParams, LegacySecurefsJsonParams,
        decrypted_securefs_params::{FullFormatParams, LiteFormatParams},
        encrypted_securefs_params::Argon2idParams,
    },
};

const PBKDF_ALGO_PKCS5: &str = "pkcs5-pbkdf2-hmac-sha256";
const PBKDF_ALGO_SCRYPT: &str = "scrypt";
const PBKDF_ALGO_ARGON2ID: &str = "argon2id";
const KEY_SIZE: usize = 32;
const IV_SIZE: usize = 12;
const MAC_SIZE: usize = 16;
const SALT_SIZE: usize = 32;

#[derive(Debug, Error)]
pub enum ParamsIoError {
    #[error("Password/keyfile is incorrect")]
    IncorrectPasswordOrKeyfile,
    #[error("Unknown pbkdf algorithm: {0}")]
    UnknownPbkdfAlgorithm(String),
    #[error("Invalid master key size")]
    InvalidMasterKeySize,
    #[error("The config file has an invalid format, even though it decrypted successfully")]
    InvalidConfigFormat {
        #[source]
        source: anyhow::Error,
    },
    #[error("The configuration file can neither be parsed as protobuf nor as JSON")]
    InvalidConfigFile,
}

type KeyType = [u8; KEY_SIZE];

fn parse_hex(hex: &str) -> Result<Vec<u8>> {
    const_hex::decode(hex).context("Failed to decode hex string")
}

fn hmac_sha256(base_key: &[u8], key_stream: &mut dyn Stream) -> Result<KeyType> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(base_key).context("HMAC initialization failed")?;
    let mut buffer = vec![0u8; 4096];
    let mut offset = 0;
    loop {
        let sz = key_stream.read(&mut buffer, offset)?;
        if sz == 0 {
            break;
        }
        Mac::update(&mut mac, &buffer[..sz as usize]);
        offset += sz;
    }
    let result = mac.finalize().into_bytes();
    Ok(result.into())
}

fn legacy_compute_password_derived_key(
    legacy: &LegacySecurefsJsonParams,
    password: &[u8],
    effective_salt: &[u8],
) -> Result<KeyType> {
    let mut result = [0u8; KEY_SIZE];
    if legacy.pbkdf == PBKDF_ALGO_ARGON2ID {
        let params = argon2::Params::new(
            legacy.argon2_m_cost,
            legacy.iterations,
            legacy.argon2_p,
            Some(KEY_SIZE),
        )?;
        let argon2 =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        argon2.hash_password_into(password, effective_salt, &mut result)?;
    } else if legacy.pbkdf == PBKDF_ALGO_SCRYPT {
        let log_n = (f64::from(legacy.iterations).log2().round()) as u8;
        let params = scrypt::Params::new(log_n, legacy.scrypt_r, legacy.scrypt_p, KEY_SIZE)?;
        scrypt::scrypt(password, effective_salt, &params, &mut result)?;
    } else if legacy.pbkdf == PBKDF_ALGO_PKCS5 || legacy.pbkdf.is_empty() {
        pbkdf2::<Hmac<Sha256>>(password, effective_salt, legacy.iterations, &mut result)?;
    } else {
        bail!(ParamsIoError::UnknownPbkdfAlgorithm(legacy.pbkdf.clone()));
    }
    Ok(result)
}

fn try_legacy_password_derived_key(
    legacy: &LegacySecurefsJsonParams,
    password: &[u8],
    key_stream: Option<&mut dyn Stream>,
    mut try_func: impl FnMut(&KeyType) -> Result<bool>,
) -> Result<bool> {
    let original_salt = parse_hex(&legacy.salt)?;

    let Some(key_stream) = key_stream else {
        let key = legacy_compute_password_derived_key(legacy, password, &original_salt)?;
        return try_func(&key);
    };

    let effective_salt_1 = hmac_sha256(&original_salt, key_stream)?;
    let key1 = legacy_compute_password_derived_key(legacy, password, &effective_salt_1)?;
    if try_func(&key1)? {
        return Ok(true);
    }

    let key_base = legacy_compute_password_derived_key(legacy, password, &original_salt)?;
    let key2 = hmac_sha256(&key_base, key_stream)?;
    try_func(&key2)
}

fn get_version_header(version: u32) -> Result<&'static [u8]> {
    match version {
        1 | 2 | 3 => Ok(b"version=1"), // Legacy mistake that we have to carry on
        4 => Ok(b"version=4"),
        _ => bail!("Unknown format version: {}", version),
    }
}

fn compute_password_derived_key(
    encparams: &EncryptedSecurefsParams,
    password: &[u8],
    key_stream: Option<&mut dyn Stream>,
) -> Result<KeyType> {
    let mut effective_salt: Cow<'_, [u8]> = encparams.salt.as_slice().into();

    if let Some(ks) = key_stream {
        let hmac_res = hmac_sha256(&encparams.salt, ks)?;
        effective_salt = hmac_res.to_vec().into();
    }

    let argon2_params = encparams.argon2id_params();

    let params = argon2::Params::new(
        argon2_params.memory_cost,
        argon2_params.time_cost,
        argon2_params.parallelism,
        Some(KEY_SIZE),
    )?;

    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = [0u8; KEY_SIZE];
    argon2.hash_password_into(password, &effective_salt, &mut key)?;

    Ok(key)
}

pub fn decrypt_legacy(
    legacy: &LegacySecurefsJsonParams,
    password: &[u8],
    key_stream: Option<&mut dyn Stream>,
) -> Result<DecryptedSecurefsParams> {
    let mut result = DecryptedSecurefsParams::new();
    {
        let size_params = result.size_params.mut_or_insert_default();
        size_params.block_size = legacy.block_size.unwrap_or(4096);
        size_params.iv_size = legacy.iv_size.unwrap_or(32);
        size_params.max_padding_size = legacy.max_padding;
    }

    let mut master_key = Vec::new();

    let success = try_legacy_password_derived_key(legacy, password, key_stream, |wrapping_key| {
        let iv = parse_hex(&legacy.encrypted_key.iv)?;
        let mac = parse_hex(&legacy.encrypted_key.mac)?;
        let ciphertext = parse_hex(&legacy.encrypted_key.ciphertext)?;
        let header = get_version_header(legacy.version)?;

        let cipher = DynamicIvAes256Gcm::new(wrapping_key.try_into()?);

        master_key.resize(ciphertext.len(), 0);
        Ok(cipher.decrypt(
            &iv,
            header,
            &ciphertext,
            mac.as_slice().try_into()?,
            &mut master_key,
        )?)
    })?;

    if !success {
        bail!(ParamsIoError::IncorrectPasswordOrKeyfile);
    }

    if legacy.version == 4 {
        if master_key.len() != 3 * KEY_SIZE && master_key.len() != 4 * KEY_SIZE {
            bail!(ParamsIoError::InvalidMasterKeySize);
        }
        let mut lite = LiteFormatParams::new();
        lite.name_key = master_key[0..KEY_SIZE].to_vec();
        lite.content_key = master_key[KEY_SIZE..2 * KEY_SIZE].to_vec();
        lite.xattr_key = master_key[2 * KEY_SIZE..3 * KEY_SIZE].to_vec();
        if master_key.len() == 4 * KEY_SIZE {
            lite.padding_key = master_key[3 * KEY_SIZE..4 * KEY_SIZE].to_vec();
        }
        if legacy.long_name_component {
            lite.long_name_threshold = Some(128);
        }

        use crate::protos::params::decrypted_securefs_params::Format_specific_params;
        result.format_specific_params = Some(Format_specific_params::LiteFormatParams(lite));
    } else {
        let mut full = FullFormatParams::new();
        full.master_key = master_key;
        if legacy.version == 1 {
            full.legacy_file_table_io = true;
        }
        if legacy.version == 3 {
            full.store_time = true;
        }
        use crate::protos::params::decrypted_securefs_params::Format_specific_params;
        result.format_specific_params = Some(Format_specific_params::FullFormatParams(full));
    }

    Ok(result)
}

pub fn decrypt_encrypted(
    encparams: &EncryptedSecurefsParams,
    password: &[u8],
    key_stream: Option<&mut dyn Stream>,
) -> Result<DecryptedSecurefsParams> {
    let wrapping_key = compute_password_derived_key(encparams, password, key_stream)?;

    let cipher = DynamicIvAes256Gcm::new(wrapping_key.as_slice().try_into()?);
    let (plaintext, success) = cipher.decrypt_alloc(
        &encparams.iv,
        &[],
        &encparams.ciphertext,
        encparams.mac.as_slice().try_into()?,
    )?;
    if !success {
        bail!(ParamsIoError::IncorrectPasswordOrKeyfile);
    }

    let result = DecryptedSecurefsParams::parse_from_bytes(&plaintext)
        .map_err(|e| ParamsIoError::InvalidConfigFormat { source: e.into() })?;

    Ok(result)
}

pub fn encrypt(
    decparams: &DecryptedSecurefsParams,
    argon2id_params: &Argon2idParams,
    password: &[u8],
    key_stream: Option<&mut dyn Stream>,
) -> Result<EncryptedSecurefsParams> {
    let mut result = EncryptedSecurefsParams::new();
    result.iv.resize(IV_SIZE, 0);
    fill_with_random(&mut result.iv);
    result.salt.resize(SALT_SIZE, 0);
    fill_with_random(&mut result.salt);
    result.mut_argon2id_params().clone_from(argon2id_params);

    let plaintext = decparams.write_to_bytes()?;

    let wrapping_key = compute_password_derived_key(&result, password, key_stream)?;

    let cipher = DynamicIvAes256Gcm::new(wrapping_key.as_slice().try_into()?);
    let (ciphertext, tag) = cipher.encrypt_alloc(&result.iv, &[], &plaintext)?;
    result.ciphertext = ciphertext;
    result.mac = tag.to_vec();

    Ok(result)
}

pub fn decrypt(
    content: &[u8],
    password: &[u8],
    key_stream: Option<&mut dyn Stream>,
) -> Result<DecryptedSecurefsParams> {
    if let Ok(encparams) = EncryptedSecurefsParams::parse_from_bytes(content) {
        return decrypt_encrypted(&encparams, password, key_stream);
    }

    let content_str = std::str::from_utf8(content).unwrap_or("");
    if let Ok(legacy) =
        protobuf_json_mapping::parse_from_str::<LegacySecurefsJsonParams>(content_str)
    {
        return decrypt_legacy(&legacy, password, key_stream);
    }

    bail!(ParamsIoError::InvalidConfigFile);
}

#[cfg(test)]
mod test {
    use crate::stream::StdIoStream;

    use super::*;
    use std::{fs::File, path::Path};
    #[test]
    fn test_decrypt_all() -> Result<()> {
        let default_argon2id_params = Argon2idParams {
            time_cost: 4,
            memory_cost: 64,
            parallelism: 2,
            special_fields: Default::default(),
        };
        let root_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("test/reference");
        let dirs = vec![
            "1",
            "1-padded",
            "2",
            "2-padded",
            "3",
            "3-padded",
            "4",
            "4-padded",
            "new-full",
            "new-full-padded",
            "new-lite",
            "new-lite-padded",
        ];

        for dir in dirs {
            let dir_path = root_dir.join(dir);
            assert!(dir_path.is_dir());

            for entry in std::fs::read_dir(&dir_path)? {
                let entry = entry?;
                let path = entry.path();
                let name = path.file_name().unwrap().to_string_lossy();

                if (name.starts_with(".securefs") && name.ends_with(".json"))
                    || (name.starts_with(".config") && name.ends_with(".pb"))
                {
                    let mut password = " ";
                    if name.to_uppercase().contains("PASSWORD") {
                        password = "abc";
                    }

                    let mut key_stream = if name.to_uppercase().contains("KEYFILE") {
                        Some(StdIoStream::from(File::open(root_dir.join("keyfile"))?))
                    } else {
                        None
                    };

                    let content = std::fs::read(&path)?;
                    let dec = decrypt(
                        &content,
                        password.as_bytes(),
                        key_stream.as_mut().map(|s| s as &mut dyn Stream),
                    )?;

                    let decrypted_pb_path = dir_path.join(".decrypted.pb");
                    let expected_bytes = std::fs::read(&decrypted_pb_path).with_context(|| {
                        format!("Failed to read {}", decrypted_pb_path.display())
                    })?;
                    let expected = DecryptedSecurefsParams::parse_from_bytes(&expected_bytes)?;

                    assert_eq!(dec, expected, "Mismatch in {}", path.display());

                    let encrypted_again = encrypt(
                        &dec,
                        &default_argon2id_params,
                        password.as_bytes(),
                        key_stream.as_mut().map(|s| s as &mut dyn Stream),
                    )?;
                    let decrypted_again = decrypt(
                        encrypted_again.write_to_bytes()?.as_slice(),
                        password.as_bytes(),
                        key_stream.as_mut().map(|s| s as &mut dyn Stream),
                    )?;
                    assert_eq!(dec, decrypted_again);
                }
            }
        }
        Ok(())
    }
}

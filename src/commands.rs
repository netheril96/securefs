use std::{
    borrow::Cow,
    path::{Path, PathBuf},
};

use ambassador::{Delegate, delegatable_trait};
use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use protobuf::Message;
use rand::{TryRngCore, rngs::OsRng};
use tracing::error_span;

use crate::{
    params_io::{decrypt_encrypted, encrypt},
    protos::params::{
        DecryptedSecurefsParams, EncryptedSecurefsParams, InternalMountData, MountOptions,
        decrypted_securefs_params::{LiteFormatParams, SizeParams},
        encrypted_securefs_params::Argon2idParams,
        mount_options::MountByKernelExt,
    },
    stream::StdIoStream,
};

pub const COMPAT_VERSION: u32 = 5;
pub const EMPTY_PASSWORD_FOR_KEYFILE: &str = " ";

#[delegatable_trait]
pub trait ConsumingRunnable {
    fn run(self) -> anyhow::Result<()>;
}

#[derive(Parser, Debug, Delegate)]
#[delegate(ConsumingRunnable, target = "command")]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug, Delegate)]
#[delegate(ConsumingRunnable)]
enum Commands {
    Create(CreateCommand),
    Mount(MountCommand),
    C(CreateCommand),
    M(MountCommand),
}

#[derive(Args, Debug)]
struct CreateCommand {
    #[arg(long, value_enum, short)]
    format: Format,

    /// Where the encrypted data should be stored in.
    data_dir: Option<PathBuf>,

    /// The location of the configuration file
    ///
    /// The config file contains all of the data format options and the
    /// encrypted keys. By default, this is ".config.pb" under the data_dir.
    #[arg(long)]
    config_file: Option<PathBuf>,

    #[command(flatten)]
    auth: AuthArg,

    #[command(flatten)]
    argon2: Argon2idArgs,
}

fn generate_master_key() -> Vec<u8> {
    let mut result = vec![0u8; 32];
    OsRng {}
        .try_fill_bytes(&mut result)
        .expect("OsRng shouldn't fail");
    result
}

impl ConsumingRunnable for CreateCommand {
    fn run(self) -> anyhow::Result<()> {
        let _span = error_span!("create").entered();

        let config_path: PathBuf = if let Some(config_file) = self.config_file {
            config_file
        } else if let Some(data_dir) = self.data_dir {
            std::fs::create_dir_all(&data_dir)?;
            data_dir.join(".config.pb")
        } else {
            bail!("No config file location specified.");
        };
        let core = || {
            if self.format != Format::Lite {
                bail!("Only lite format is currently implemented");
            }
            let mut config_file = std::fs::File::create_new(&config_path)
                .with_context(|| format!("failed to create {:?} for writing", config_path))?;
            let (password, mut key_stream) = AuthOptions::from(self.auth).read(true)?;
            tracing::info!("Generating master keys...");
            let dec_params = DecryptedSecurefsParams {
            compat_version: COMPAT_VERSION,
            size_params: Some(SizeParams {
                block_size: 4096,
                iv_size: 12,
                max_padding_size: 16,
                special_fields: Default::default(),
            }).into(),
            format_specific_params: Some(crate::protos::params::decrypted_securefs_params::Format_specific_params::LiteFormatParams(LiteFormatParams {
                name_key: generate_master_key(),
                content_key: generate_master_key(),
                xattr_key: generate_master_key(),
                padding_key: generate_master_key(),
                long_name_threshold: Some(128),
                long_name_suffix: ".long".into(),
                disable_legacy_additional_encryption_after_hashing_long_name: true,
                special_fields: Default::default(),
            })),
            special_fields:Default::default(),
        };
            tracing::info!("Hashing and encrypting config...");
            let argon2idparams = Argon2idParams::from(self.argon2);
            let enc_params = encrypt(
                &dec_params,
                &argon2idparams,
                password.as_bytes(),
                key_stream.as_mut(),
            )?;
            enc_params.write_to_writer(&mut config_file)?;
            config_file
                .sync_all()
                .with_context(|| format!("failed to flush {:?}", config_path))?;
            tracing::info!("Done");
            Ok(())
        };

        match core() {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(&config_path);
                Err(e)
            }
        }
    }
}

#[derive(Args, Debug, Clone)]
struct Argon2idArgs {
    /// Memory cost of the Argon2 algorithm.
    ///
    /// It can have suffices like K, KB, KiB, M, G, etc.
    /// It must be multiples of KiB.
    #[arg(long = "argon2-m", default_value_t = 64 << 20, value_parser = parse_memory_spec)]
    memory_cost: u32,

    /// Time cost of the Argon2 algorithm.
    #[arg(long = "argon2-t", default_value_t = 4)]
    time_cost: u32,

    /// Parallelism of the Argon2 algorithm.
    #[arg(long = "argon2-p", default_value_t = 4)]
    parallelism: u32,
}

fn parse_memory_spec(m: &str) -> anyhow::Result<u32> {
    let m = m.trim();
    let upper = m.to_ascii_uppercase();

    let (multiplier, suffix_len) = if upper.ends_with("GIB") {
        (1024 * 1024 * 1024, 3)
    } else if upper.ends_with("GB") {
        (1024 * 1024 * 1024, 2)
    } else if upper.ends_with("G") {
        (1024 * 1024 * 1024, 1)
    } else if upper.ends_with("MIB") {
        (1024 * 1024, 3)
    } else if upper.ends_with("MB") {
        (1024 * 1024, 2)
    } else if upper.ends_with("M") {
        (1024 * 1024, 1)
    } else if upper.ends_with("KIB") {
        (1024, 3)
    } else if upper.ends_with("KB") {
        (1024, 2)
    } else if upper.ends_with("K") {
        (1024, 1)
    } else {
        (1, 0)
    };

    let num_part = m[..m.len() - suffix_len].trim();
    let val: u32 = num_part.parse().context("Failed to parse number")?;

    val.checked_mul(multiplier).context("Memory size overflow")
}

impl From<Argon2idArgs> for Argon2idParams {
    fn from(value: Argon2idArgs) -> Self {
        Self {
            time_cost: value.time_cost,
            memory_cost: value.memory_cost / 1024,
            parallelism: value.parallelism,
            special_fields: Default::default(),
        }
    }
}

#[derive(Args, Debug, Clone, Default)]
struct AuthArg {
    /// The password in plaintext.
    ///
    /// Specifying this in the command line may be a
    /// security risk, but the option is here for testing.
    #[arg(long)]
    password: Option<String>,

    /// The path to the keyfile.
    #[arg(long)]
    keyfile: Option<PathBuf>,

    /// Whether to ask for password on the command line.
    ///
    /// By default, if neither --password nor --keyfile is present, we will ask
    /// for password regardless. Therefore the only usage for this flag is to
    /// force asking for password when --keyfile is present. This allows
    /// additional protection as the keyfile alone won't be able to unlock the
    /// repository.
    #[arg(long)]
    ask: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AuthOptions {
    AskPassword,
    Password(String),
    Keyfile(PathBuf),
    PasswordAndKeyFile { password: String, keyfile: PathBuf },
    AskPasswordAndKeyfile { keyfile: PathBuf },
}

impl From<AuthArg> for AuthOptions {
    fn from(arg: AuthArg) -> Self {
        match (arg.password, arg.keyfile, arg.ask) {
            (Some(password), Some(keyfile), _) => Self::PasswordAndKeyFile { password, keyfile },
            (Some(password), None, _) => Self::Password(password),
            (None, Some(keyfile), true) => Self::AskPasswordAndKeyfile { keyfile },
            (None, Some(keyfile), false) => Self::Keyfile(keyfile),
            (None, None, _) => Self::AskPassword,
        }
    }
}

impl AuthOptions {
    fn read(self, confirm_ask: bool) -> anyhow::Result<(String, Option<StdIoStream>)> {
        match self {
            Self::AskPassword => {
                let password = Self::get_password(confirm_ask)?;
                Ok((password, None))
            }
            Self::Password(password) => Ok((password.clone(), None)),
            Self::Keyfile(keyfile) => Ok((
                EMPTY_PASSWORD_FOR_KEYFILE.into(),
                Some(Self::open_keyfile(&keyfile)?),
            )),
            Self::PasswordAndKeyFile { password, keyfile } => {
                Ok((password.clone(), Some(Self::open_keyfile(&keyfile)?)))
            }
            Self::AskPasswordAndKeyfile { keyfile } => {
                let password = Self::get_password(confirm_ask)?;
                Ok((password, Some(Self::open_keyfile(&keyfile)?)))
            }
        }
    }

    fn get_password(confirm_ask: bool) -> anyhow::Result<String> {
        let password = rpassword::prompt_password("Enter password:")?;
        if confirm_ask {
            let confirm = rpassword::prompt_password("Confirm password:")?;
            if password != confirm {
                bail!("Passwords do not match");
            }
        }
        Ok(password)
    }

    fn open_keyfile(path: &Path) -> anyhow::Result<StdIoStream> {
        Ok(StdIoStream::from(std::fs::File::open(path)?))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Format {
    Lite,
    Full,
}

#[derive(Args, Debug)]
struct MountCommand {
    /// Where the encrypted data should be stored in.
    data_dir: PathBuf,

    /// The mount point.
    ///
    /// On Unix, this shall be a folder path.
    /// On Windows, this can be either a folder path or a drive letter.
    mount_point: PathBuf,

    /// The location of the configuration file
    ///
    /// The config file contains all of the data format options and the
    /// encrypted keys. By default, this is ".config.pb" under the data_dir.
    #[arg(long)]
    config_file: Option<PathBuf>,

    #[command(flatten)]
    auth: AuthArg,

    /// Mount as a readonly filesystem.
    #[arg(long)]
    read_only: bool,

    /// Disable verification of data.
    #[arg(long)]
    disable_verification: bool,

    /// For lite format only, do not encrypt and decrypt file names.
    #[arg(long)]
    plain_text_names: bool,
}

impl ConsumingRunnable for MountCommand {
    fn run(mut self) -> anyhow::Result<()> {
        let span = error_span!("mount").entered();
        let mount_data = {
            let enc_params = {
                let config_path: Cow<'_, Path> = if let Some(config_file) = &self.config_file {
                    config_file.into()
                } else {
                    self.data_dir.join(".config.pb").into()
                };
                tracing::info!("Reading config file at {:?}...", config_path);
                let mut config_file = std::fs::File::open(&config_path)
                    .with_context(|| format!("failed to open {:?} for reading", config_path))?;
                let enc_params = EncryptedSecurefsParams::parse_from_reader(&mut config_file)?;
                enc_params
            };

            let (password, mut key_stream) =
                AuthOptions::from(std::mem::take(&mut self.auth)).read(false)?;
            tracing::info!("Decrypting config file ...");
            let dec_params = decrypt_encrypted(
                &enc_params,
                password.as_bytes(),
                key_stream.as_mut(),
            ).context("Failed to decrypt the config file. It is likely that the password/keyfile is wrong, or that the config file is corrupted.")?;

            if dec_params.compat_version > COMPAT_VERSION {
                bail!(
                    "The config file is created by a higher version of securefs. This old version cannot mount it or data loss may occur."
                );
            }

            InternalMountData {
                decrypted_params: Some(dec_params).into(),
                mount_options: Some(MountOptions {
                    mount_point: self.mount_point.to_string_lossy().into_owned(),
                    read_only: self.read_only,
                    disable_verification: self.disable_verification,
                    uid_override: None,
                    gid_override: None,
                    enable_xattr: true,
                    case_fold: false,
                    unicode_normalize_nfc: false,
                    plain_text_names: self.plain_text_names,
                    allow_sensitive_logging: false,
                    max_idle_seconds: 0,
                    inode_table_shard_count: 64,
                    attr_cache_seconds: Some(30),
                    mount_type_specific: Some(
                        crate::protos::params::mount_options::Mount_type_specific::MountByKernelExt(
                            MountByKernelExt {
                                special_fields: Default::default(),
                            },
                        ),
                    ),
                    special_fields: Default::default(),
                })
                .into(),
                fuse_args: {
                    let mut args = vec!["default_permissions".into()];
                    if self.read_only {
                        args.push("ro".into());
                    }
                    args
                },
                data_dir: self.data_dir.to_string_lossy().into_owned(),
                background_logging: None.into(),
                special_fields: Default::default(),
            }
        };
        drop(self);

        tracing::info!("Mounting at {:?}...", &mount_data.mount_options.mount_point);

        // The actual mounting happens multi-threaded, so for consistency, we exit the
        // span in the current thread.
        span.exit();

        #[cfg(unix)]
        return crate::lite::unix::mount(mount_data);

        #[cfg(windows)]
        return crate::lite::win::mount(mount_data);
    }
}

pub fn commands_main() -> anyhow::Result<()> {
    let args = Cli::parse();
    args.run()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}

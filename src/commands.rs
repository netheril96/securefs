use std::{
    io::Write,
    path::{Path, PathBuf},
};

use ambassador::{Delegate, delegatable_trait};
use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use protobuf::Message;
use rand::{TryRngCore, rngs::OsRng};

use crate::{
    params_io::encrypt,
    protos::params::{
        DecryptedSecurefsParams,
        decrypted_securefs_params::{LiteFormatParams, SizeParams},
        encrypted_securefs_params::Argon2idParams,
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
    C(CreateCommand),
}

#[derive(Args, Debug)]
struct CreateCommand {
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

    #[arg(long, value_enum)]
    format: Format,
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
        let config_file: PathBuf = if let Some(config_file) = self.config_file {
            config_file
        } else if let Some(data_dir) = self.data_dir {
            data_dir.join(".config.pb")
        } else {
            bail!("No config file location specified.");
        };
        let mut config_file = std::fs::File::create_new(&config_file)
            .with_context(|| format!("failed to create {:?} for writing", config_file))?;
        let (password, mut key_stream) = AuthOptions::from(self.auth).read(true)?;
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
        let argon2idparams = Argon2idParams {
            time_cost: 4,
            memory_cost: 64 << 20,
            parallelism: 4,
            special_fields: Default::default(),
        };
        let enc_params = encrypt(
            &dec_params,
            &argon2idparams,
            password.as_bytes(),
            key_stream.as_mut().map(|k| k as _),
        )?;
        enc_params.write_to_writer(&mut config_file)?;
        Ok(())
    }
}

#[derive(Args, Debug, Clone)]
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

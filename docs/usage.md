# securefs
The command strucuture is `securefs ${SUBCOMMAND} ${SUBOPTIONS}`.
See below for available subcommands and relevant options

## mount (short name: m)
Mount an existing filesystem

- **dir**: (*positional*) (required)  Directory where the data are stored
- **mount_point**: (*positional*) (required)  Mount point
- **--plain-text-names**: When enabled, securefs does not encrypt or decrypt file names. Use it at your own risk. No effect on full format.. *This is a switch arg. Default: false.*
- **--skip-dot-dot**: When enabled, securefs will not return . and .. in `readdir` calls. You should normally not need this.. *This is a switch arg. Default: false.*
- **--attr-timeout**: Number of seconds to cache file attributes. Default is 30.. *Default: 30.*
- **--noflock**: Disables the usage of file locking. Needed on some network filesystems. May cause data loss, so use it at your own risk!. *This is a switch arg. Default: false.*
- **--fssubtype**: Filesystem subtype shown when mounted. *Default: securefs.*
- **--fsname**: Filesystem name shown when mounted. *Default: securefs.*
- **--normalization**: Mode of filename normalization. Valid values: none, casefold, nfc, casefold+nfc. Defaults to nfc on macOS and none on other platforms. *Default: none.*
- **-s** or **--single**: Single threaded mode. *This is a switch arg. Default: false.*
- **-o** or **--opt**: Additional FUSE options; this may crash the filesystem; use only for testing!. *This option can be specified multiple times.*
- **--log**: Path of the log file (may contain sensitive information). *Unset by default.*
- **--trace**: Trace all calls into `securefs` (implies --verbose). *This is a switch arg. Default: false.*
- **-v** or **--verbose**: Logs more verbose messages. *This is a switch arg. Default: false.*
- **-b** or **--background**: Run securefs in the background (currently no effect on Windows). *This is a switch arg. Default: false.*
- **--askpass**: When set to true, ask for password even if a key file is used. password+keyfile provides even stronger security than one of them alone.. *This is a switch arg. Default: false.*
- **--keyfile**: An optional path to a key file to use in addition to or in place of password. *Unset by default.*
- **--pass**: Password (prefer manually typing or piping since those methods are more secure). *Unset by default.*
- **--config**: Full path name of the config file. ${data_dir}/.securefs.json by default. *Unset by default.*
## create (short name: c)
Create a new filesystem

- **dir**: (*positional*) (required)  Directory where the data are stored
- **--max-padding**: Maximum number of padding (the unit is byte) to add to all files in order to obfuscate their sizes. Each file has a different padding. Enabling this has a large performance cost.. *Default: 0.*
- **--pbkdf**: The algorithm to stretch passwords. Use argon2id for maximum protection (default), or pkcs5-pbkdf2-hmac-sha256 for compatibility with old versions of securefs. *Default: argon2id.*
- **--block-size**: Block size for files (ignored for fs format 1). *Default: 4096.*
- **--store_time**: alias for "--format 3", enables the extension where timestamp are stored and encrypted. *This is a switch arg. Default: false.*
- **--format**: The filesystem format version (1,2,3,4). *Default: 4.*
- **-r** or **--rounds**: Specify how many rounds of key derivation are applied (0 for automatic). *Default: 0.*
- **--iv-size**: The IV size (ignored for fs format 1). *Default: 12.*
- **--askpass**: When set to true, ask for password even if a key file is used. password+keyfile provides even stronger security than one of them alone.. *This is a switch arg. Default: false.*
- **--keyfile**: An optional path to a key file to use in addition to or in place of password. *Unset by default.*
- **--pass**: Password (prefer manually typing or piping since those methods are more secure). *Unset by default.*
- **--config**: Full path name of the config file. ${data_dir}/.securefs.json by default. *Unset by default.*
## chpass
Change password/keyfile of existing filesystem

- **dir**: (*positional*) (required)  Directory where the data are stored
- **--pbkdf**: The algorithm to stretch passwords. Use argon2id for maximum protection (default), or pkcs5-pbkdf2-hmac-sha256 for compatibility with old versions of securefs. *Default: argon2id.*
- **--newpass**: The new password (prefer manually typing or piping since those methods are more secure). *Unset by default.*
- **--oldpass**: The old password (prefer manually typing or piping since those methods are more secure). *Unset by default.*
- **--asknewpass**: When set to true, ask for password even if a key file is used. password+keyfile provides even stronger security than one of them alone.. *This is a switch arg. Default: false.*
- **--askoldpass**: When set to true, ask for password even if a key file is used. password+keyfile provides even stronger security than one of them alone.. *This is a switch arg. Default: false.*
- **--newkeyfile**: Path to new key file. *Unset by default.*
- **--oldkeyfile**: Path to original key file. *Unset by default.*
- **--config**: Full path name of the config file. ${data_dir}/.securefs.json by default. *Unset by default.*
- **-r** or **--rounds**: Specify how many rounds of key derivation are applied (0 for automatic). *Default: 0.*
## fix
Try to fix errors in an existing filesystem

- **dir**: (*positional*) (required)  Directory where the data are stored
- **--askpass**: When set to true, ask for password even if a key file is used. password+keyfile provides even stronger security than one of them alone.. *This is a switch arg. Default: false.*
- **--keyfile**: An optional path to a key file to use in addition to or in place of password. *Unset by default.*
- **--pass**: Password (prefer manually typing or piping since those methods are more secure). *Unset by default.*
- **--config**: Full path name of the config file. ${data_dir}/.securefs.json by default. *Unset by default.*
## version (short name: v)
Show version of the program

## info (short name: i)
Display information about the filesystem

- **path**: (*positional*) (required)  Directory or the filename of the config file
## doc
Display the full help message of all commands in markdown format


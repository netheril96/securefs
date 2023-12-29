# securefs
The command strucuture is `securefs ${SUBCOMMAND} ${SUBOPTIONS}`.
See below for available subcommands and relevant options

## mount (short name: m)
Mount an existing filesystem

- **--plain-text-names**: When enabled, securefs does not encrypt or decrypt file names. Use it at your own risk. No effect on full format.. *This is a switch arg. Default: false.*
- **--skip-dot-dot**: When enabled, securefs will not return . and .. in `readdir` calls. You should normally not need this.. *This is a switch arg. Default: false.*
- **--attr-timeout**: Number of seconds to cache file attributes. Default is 30.. *Default: 30.*
- **--noflock**: Disables the usage of file locking. Needed on some network filesystems. May cause data loss, so use it at your own risk!. *This is a switch arg. Default: false.*
- **--fssubtype**: Filesystem subtype shown when mounted. *Default: securefs.*
- **--fsname**: Filesystem name shown when mounted. *Default: securefs.*
- **--normalization**: Mode of filename normalization. Valid values: none, casefold, nfc, casefold+nfc. Defaults to nfc on macOS and none on other platforms. *Default: none.*
- **-s** **--single**: Single threaded mode. *This is a switch arg. Default: false.*
- **-o** **--opt**: Additional FUSE options; this may crash the filesystem; use only for testing!. *This option can be specified multiple times.*
- **--log**: Path of the log file (may contain sensitive information). *Default: .*
- **--trace**: Trace all calls into `securefs` (implies --verbose). *This is a switch arg. Default: false.*
- **-v** **--verbose**: Logs more verbose messages. *This is a switch arg. Default: false.*
- **-b** **--background**: Run securefs in the background (currently no effect on Windows). *This is a switch arg. Default: false.*
- **--askpass**: When set to true, ask for password even if a key file is used. password+keyfile provides even stronger security than one of them alone.. *This is a switch arg. Default: false.*
- **--keyfile**: An optional path to a key file to use in addition to or in place of password. *Default: .*
- **--pass**: Password (prefer manually typing or piping since those methods are more secure). *Default: .*
- **--config**: Full path name of the config file. ${data_dir}/.securefs.json by default. *Default: .*
- **--** **--ignore_rest**: Ignores the rest of the labeled arguments following this flag.. *This is a switch arg. Default: false.*
- **--version**: Displays version information and exits.. *This is a switch arg. Default: false.*
- **-h** **--help**: Displays usage information and exits.. *This is a switch arg. Default: false.*
- **dir**: (*positional*) (required)  Directory where the data are stored
- **mount_point**: (*positional*) (required)  Mount point
## create (short name: c)
Create a new filesystem

- **--max-padding**: Maximum number of padding (the unit is byte) to add to all files in order to obfuscate their sizes. Each file has a different padding. Enabling this has a large performance cost.. *Default: 0.*
- **--pbkdf**: The algorithm to stretch passwords. Use argon2id for maximum protection (default), or pkcs5-pbkdf2-hmac-sha256 for compatibility with old versions of securefs. *Default: argon2id.*
- **--block-size**: Block size for files (ignored for fs format 1). *Default: 4096.*
- **--store_time**: alias for "--format 3", enables the extension where timestamp are stored and encrypted. *This is a switch arg. Default: false.*
- **--format**: The filesystem format version (1,2,3,4). *Default: 4.*
- **-r** **--rounds**: Specify how many rounds of key derivation are applied (0 for automatic). *Default: 0.*
- **--iv-size**: The IV size (ignored for fs format 1). *Default: 12.*
- **--askpass**: When set to true, ask for password even if a key file is used. password+keyfile provides even stronger security than one of them alone.. *This is a switch arg. Default: false.*
- **--keyfile**: An optional path to a key file to use in addition to or in place of password. *Default: .*
- **--pass**: Password (prefer manually typing or piping since those methods are more secure). *Default: .*
- **--config**: Full path name of the config file. ${data_dir}/.securefs.json by default. *Default: .*
- **--** **--ignore_rest**: Ignores the rest of the labeled arguments following this flag.. *This is a switch arg. Default: false.*
- **--version**: Displays version information and exits.. *This is a switch arg. Default: false.*
- **-h** **--help**: Displays usage information and exits.. *This is a switch arg. Default: false.*
- **dir**: (*positional*) (required)  Directory where the data are stored
## chpass
Change password/keyfile of existing filesystem

- **--pbkdf**: The algorithm to stretch passwords. Use argon2id for maximum protection (default), or pkcs5-pbkdf2-hmac-sha256 for compatibility with old versions of securefs. *Default: argon2id.*
- **--newpass**: The new password (prefer manually typing or piping since those methods are more secure). *Default: .*
- **--oldpass**: The old password (prefer manually typing or piping since those methods are more secure). *Default: .*
- **--asknewpass**: When set to true, ask for password even if a key file is used. password+keyfile provides even stronger security than one of them alone.. *This is a switch arg. Default: false.*
- **--askoldpass**: When set to true, ask for password even if a key file is used. password+keyfile provides even stronger security than one of them alone.. *This is a switch arg. Default: false.*
- **--newkeyfile**: Path to new key file. *Default: .*
- **--oldkeyfile**: Path to original key file. *Default: .*
- **--config**: Full path name of the config file. ${data_dir}/.securefs.json by default. *Default: .*
- **-r** **--rounds**: Specify how many rounds of key derivation are applied (0 for automatic). *Default: 0.*
- **--** **--ignore_rest**: Ignores the rest of the labeled arguments following this flag.. *This is a switch arg. Default: false.*
- **--version**: Displays version information and exits.. *This is a switch arg. Default: false.*
- **-h** **--help**: Displays usage information and exits.. *This is a switch arg. Default: false.*
- **dir**: (*positional*) (required)  Directory where the data are stored
## fix
Try to fix errors in an existing filesystem

- **--askpass**: When set to true, ask for password even if a key file is used. password+keyfile provides even stronger security than one of them alone.. *This is a switch arg. Default: false.*
- **--keyfile**: An optional path to a key file to use in addition to or in place of password. *Default: .*
- **--pass**: Password (prefer manually typing or piping since those methods are more secure). *Default: .*
- **--config**: Full path name of the config file. ${data_dir}/.securefs.json by default. *Default: .*
- **--** **--ignore_rest**: Ignores the rest of the labeled arguments following this flag.. *This is a switch arg. Default: false.*
- **--version**: Displays version information and exits.. *This is a switch arg. Default: false.*
- **-h** **--help**: Displays usage information and exits.. *This is a switch arg. Default: false.*
- **dir**: (*positional*) (required)  Directory where the data are stored
## version (short name: v)
Show version of the program

- **--** **--ignore_rest**: Ignores the rest of the labeled arguments following this flag.. *This is a switch arg. Default: false.*
- **--version**: Displays version information and exits.. *This is a switch arg. Default: false.*
- **-h** **--help**: Displays usage information and exits.. *This is a switch arg. Default: false.*
## info (short name: i)
Display information about the filesystem

- **--** **--ignore_rest**: Ignores the rest of the labeled arguments following this flag.. *This is a switch arg. Default: false.*
- **--version**: Displays version information and exits.. *This is a switch arg. Default: false.*
- **-h** **--help**: Displays usage information and exits.. *This is a switch arg. Default: false.*
- **path**: (*positional*) (required)  Directory or the filename of the config file
## doc
Display the full help message of all commands in markdown format

- **--** **--ignore_rest**: Ignores the rest of the labeled arguments following this flag.. *This is a switch arg. Default: false.*
- **--version**: Displays version information and exits.. *This is a switch arg. Default: false.*
- **-h** **--help**: Displays usage information and exits.. *This is a switch arg. Default: false.*

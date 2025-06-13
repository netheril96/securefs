# securefs
The command strucuture is `securefs ${SUBCOMMAND} ${SUBOPTIONS}`.
See below for available subcommands and relevant options

## mount (short name: m)
Mount an existing filesystem

- **dir**: (*positional*) (required)  Directory where the data are stored
- **mount_point**: (*positional*) (required)  Mount point
- **--config**: Full path name of the config file. ${data_dir}/.config.pb by default. *Unset by default.*
- **--pass**: Password (prefer manually typing or piping since those methods are more secure). *Unset by default.*
- **--keyfile**: An optional path to a key file to use in addition to or in place of password. *Unset by default.*
- **--askpass**: When provided, ask for password even if a key file is used. password+keyfile provides even stronger security than one of them alone.. *This is a switch arg. Default: false.*
- **-s** or **--single**: Single threaded mode. *This is a switch arg. Default: false.*
- **-b** or **--background**: Spawn a child process to mount in the background (also available on Windows). *This is a switch arg. Default: false.*
- **-i** or **--insecure**: Disable all integrity verification (insecure mode). *This is a switch arg. Default: false.*
- **-x** or **--noxattr**: Disable built-in xattr support. *This is a switch arg. Default: false.*
- **-v** or **--verbose**: Logs more verbose messages. *This is a switch arg. Default: false.*
- **--trace**: Trace all calls into `securefs` (implies --verbose). *This is a switch arg. Default: false.*
- **--log**: Path of the log file (may contain sensitive information). *Unset by default.*
- **-o** or **--opt**: Additional FUSE options; this may crash the filesystem; use only for testing!. *This option can be specified multiple times.*
- **--fsname**: Filesystem name shown when mounted. *Default: securefs.*
- **--fssubtype**: Filesystem subtype shown when mounted. *Default: securefs.*
- **--noflock**: Disables the usage of file locking. Needed on some network filesystems. May cause data loss, so use it at your own risk!. *This is a switch arg. Default: false.*
- **--use-ino**: Asking libfuse to use the inode number reported by securefs as is. This may be needed if the application reads inode number. For full format, this should always be on. For lite format, the user needs to manually turn this on when the underlying filesystem has stable inode numbers (e.g. ext4, APFS, ZFS).. *Default: auto.*
- **--normalization**: Mode of filename normalization. Valid values: none, casefold, nfc, casefold+nfc. Defaults to nfc on macOS and none on other platforms. *Default: none.*
- **--attr-timeout**: Number of seconds to cache file attributes. Default is 30.. *Default: 30.*
- **--skip-dot-dot**: A no-op option retained for backwards compatibility. *This is a switch arg. Default: false.*
- **--plain-text-names**: When enabled, securefs does not encrypt or decrypt file names. Use it at your own risk. No effect on full format.. *This is a switch arg. Default: false.*
- **--uid-override**: Forces every file to be owned by this uid in the virtual filesystem. If the value is -1, then no override is in place. *Default: -1.*
- **--gid-override**: Forces every file to be owned by this gid in the virtual filesystem. If the value is -1, then no override is in place. *Default: -1.*
- **--allow-sensitive-logging**: Allow sensitive information in logs. *This is a switch arg. Default: false.*
- **--max-idle-seconds**: Maximum idle time before the filesystem is unmounted automatically. Default is 0 (no auto unmount).. *Default: 0.*
## create (short name: c)
Create a new filesystem

- **dir**: (*positional*) (required)  Directory where the data are stored
- **--config**: Full path name of the config file. ${data_dir}/.config.pb by default. *Unset by default.*
- **--pass**: Password (prefer manually typing or piping since those methods are more secure). *Unset by default.*
- **--keyfile**: An optional path to a key file to use in addition to or in place of password. *Unset by default.*
- **--askpass**: When provided, ask for password even if a key file is used. password+keyfile provides even stronger security than one of them alone.. *This is a switch arg. Default: false.*
- **--argon2-t**: The time cost for argon2 algorithm. *Default: 30.*
- **--argon2-m**: The memory cost for argon2 algorithm (in terms of KiB). *Default: 262144.*
- **--argon2-p**: The parallelism for argon2 algorithm. *Default: 4.*
- **-f** or **--format**: The format type of the repository. Either lite or full. Lite repos are faster and more reliable, but the directory structure itself is visible. Full repos offer more privacy at the cost of performance and ease of synchronization.. *Default: lite.*
- **--iv-size**: The IV size (ignored for fs format 1). *Default: 12.*
- **--block-size**: Block size for files (ignored for fs format 1). *Default: 4096.*
- **--max-padding**: Maximum number of padding (the unit is byte) to add to all files in order to obfuscate their sizes. Each file has a different padding. Enabling this has a large performance cost.. *Default: 0.*
- **--long-name-threshold**: (For lite format only) when the filename component exceeds this length, it will be stored encrypted in a SQLite database.. *Default: 128.*
- **--long-name-suffix**: (For lite format only) The suffix to append to the encrypted names to indicate its real name is in DB.. *Default: .ll.*
- **--case**: Either sensitive or insensitive. Changes how full format stores its filenames. Not applicable to lite format.. *Default: sensitive.*
- **--uninorm**: Either sensitive or insensitive. Changes how full format stores its filenames. Not applicable to lite format.. *Default: sensitive.*
## chpass
Change password/keyfile of existing filesystem

- **dir**: (*positional*) (required)  Directory where the data are stored
- **--config**: Full path name of the config file. ${data_dir}/.config.pb by default. *Unset by default.*
- **--oldkeyfile**: Path to original key file. *Unset by default.*
- **--newkeyfile**: Path to new key file. *Unset by default.*
- **--askoldpass**: When set to true, ask for password even if a key file is used. password+keyfile provides even stronger security than one of them alone.. *This is a switch arg. Default: false.*
- **--asknewpass**: When set to true, ask for password even if a key file is used. password+keyfile provides even stronger security than one of them alone.. *This is a switch arg. Default: false.*
- **--oldpass**: The old password (prefer manually typing or piping since those methods are more secure). *Unset by default.*
- **--newpass**: The new password (prefer manually typing or piping since those methods are more secure). *Unset by default.*
- **--argon2-t**: The time cost for argon2 algorithm. *Default: 30.*
- **--argon2-m**: The memory cost for argon2 algorithm (in terms of KiB). *Default: 262144.*
- **--argon2-p**: The parallelism for argon2 algorithm. *Default: 4.*
## version (short name: v)
Show version of the program

## info (short name: i)
Display information about the filesystem in the JSON format

- **dir**: (*positional*) (required)  Directory where the data are stored
- **--config**: Full path name of the config file. ${data_dir}/.config.pb by default. *Unset by default.*
- **--pass**: Password (prefer manually typing or piping since those methods are more secure). *Unset by default.*
- **--keyfile**: An optional path to a key file to use in addition to or in place of password. *Unset by default.*
- **--askpass**: When provided, ask for password even if a key file is used. password+keyfile provides even stronger security than one of them alone.. *This is a switch arg. Default: false.*
- **--unmask**: Disables the masking of master keys in the output. *This is a switch arg. Default: false.*
## migrate-long-name
Migrate a lite format repository without long name support.

- **dir**: (*positional*) (required)  Directory where the data are stored
- **--config**: Full path name of the config file. ${data_dir}/.config.pb by default. *Unset by default.*
- **--pass**: Password (prefer manually typing or piping since those methods are more secure). *Unset by default.*
- **--keyfile**: An optional path to a key file to use in addition to or in place of password. *Unset by default.*
- **--askpass**: When provided, ask for password even if a key file is used. password+keyfile provides even stronger security than one of them alone.. *This is a switch arg. Default: false.*
- **--argon2-t**: The time cost for argon2 algorithm. *Default: 30.*
- **--argon2-m**: The memory cost for argon2 algorithm (in terms of KiB). *Default: 262144.*
- **--argon2-p**: The parallelism for argon2 algorithm. *Default: 4.*
- **--long-name-suffix**: (For lite format only) The suffix to append to the encrypted names to indicate its real name is in DB.. *Default: .ll.*
## ismount
Check if the given path is a securefs mount point

- **mount_point**: (*positional*) (required)  Mount point to check
## unmount (short name: u)
Unmount the given securefs mount point

- **mount_point**: (*positional*) (required)  Mount point to unmount
## doc
Display the full help message of all commands in markdown format


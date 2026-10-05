# Helpful Info for SecureFS users

This document covers random topics that may be of use to users of SecureFS.

## Remote Mounting Considerations

### GVFS incompatibility and solution

At this time SecureFS does not work with GVFS (GNOME Virtual File System), which is used in Ubuntu and other GNOME-based Linux distributions. Instead, install and use SSHFS which is confirmed to work.

### Remote mounting MacOS

MacOS has a low number of available file descriptors by default. When running SecureFS on Mac, this number is automatically raised. However, when remote mounting there is no way to automatically raise this, so it must be raised manually. 

On your mac, run `launchctl limit maxfiles 8192 unlimited` (it doesn't persist across reboot) before you mount the sshfs volume. Or you can run this with ssh, exit it, and then mount sshfs.

### Other issues

In lite mode, files may appear to upload correctly, however an error spam of "Operation not permitted" may be printed to the console. This is because FUSE and SSHFS in particular all have problems mapping user ids. If it doesn't affect your usage, you can ignore these logs.

### Renaming the SecureFS meta file

You can rename the `.securefs.json` file however you like. You can even move it to another location. During mounting, specify the whole path of the file by `--config` option.

## Security Audits

SecureFS has not been formally audited for security.

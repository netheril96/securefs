# securefs

`securefs` is a filesystem in userspace (FUSE) with transparent encryption (when writing) and decryption (when reading).

`securefs` mounts a regular directory onto a mount point. The mount point appears as a regular filesystem, where one can read/write/create files, directories and symbolic links. The underlying directory will be automatically updated to contain the encrypted and authenticated contents.

## Motivation

From sensitive financial records to personal diaries and collection of guilty pleasures, we all have something to keep private from prying eyes. Especially when we store our files in the cloud, the company and the NSA may well get their hands upon it. The best protection we can afford ourselves is **cryptography**, the discipline developed by mathematicians and military originally to keep the national secrets.

Security, however, is often at odds with convenience, and people easily grow tired of the hassle and revert to no protection at all. Consider the case of protecting our files either locally or in the cloud: we have to encrypt the files before committing to the cloud and decrypt it every time we need to read and write. Worse still, such actions leave unencrypted traces on our hard drive. If we store data in the cloud, another issue arise: manual encryption and decryption prevent files from being synced efficiently.

`securefs` is intended to make the experience as smooth as possible so that the security and convenience do not conflict. After mounting the virtual filesystem, everything just works&#8482;.

## Comparison

There are already many encrypting filesystem in widespread use. Some notable ones are TrueCrypt, FileVault, BitLocker, eCryptFS, encfs and gocryptfs. `securefs` differs from them in that it is the only one with all of the following features:

* [Authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption) (hence secure against chosen ciphertext attacks)
* [Probabilistic encryption](https://en.wikipedia.org/wiki/Probabilistic_encryption) (hence provides semantical security)
* Supported on all major platforms (Mac, Linux, BSDs and Windows)
* Efficient cloud synchronization (not a single preallocated file as container)

## Install

[![Build Status](https://api.travis-ci.org/netheril96/securefs.svg?branch=master)](https://travis-ci.org/netheril96/securefs)

### Dependency: FUSE

On macOS, you need [osxfuse](https://osxfuse.github.io).

On Debian based Linux distro, `sudo apt-get install fuse libfuse-dev`.

On RPM based Linux, `sudo yum install fuse fuse-devel`.

On Windows, you need [WinFsp](https://github.com/billziss-gh/winfsp/releases).

### Install with Homebrew

```
brew install securefs
```

### Windows

Windows users can download prebuilt package from the releases section. It depends on VC++ 2015 redistribution package.

### Manual Build

Use `cmake` the generate build files then build it. It requires a sufficiently new compiler that supports enough of C++11 (such as g++ 4.8, clang 3.4 or VC++ 2015).

## Basic usage

*It is recommended to disable or encrypt the swap and hibernation file. Otherwise plaintext and keys stored in the main memory may be written to disk by the OS at any time.*

Examples:

```bash
securefs --help
securefs create ~/Secret
securefs chpass ~/Secret
securefs mount ~/Secret ~/Mount # press Ctrl-C to unmount
securefs m -h # m is an alias for mount, -h tell you all the flags
```

## Lite and full mode

There are two categories of filesystem format.

The **lite** format simply encrypts filenames and file contents separately, similar to how `encfs` operates, although with more security.

The **full** format maps files, directory and symlinks in the virtual filesystem all to regular files in the underlying filesystem. The directory structure is flattened and recorded as B-trees in files.

The lite format has become the default on Unix-like operating systems as it is much faster and features easier conflict resolution, especially when used with DropBox, Google Drive, etc. The full format, however, leaks fewer information about the filesystem hierarchy, runs relatively independent of the features of the underlying filesystem, and is in general more secury.

To request full format, which is no longer the default, run `securefs create --format 2`.

## Design and algorithms

See [here](docs/design.md).

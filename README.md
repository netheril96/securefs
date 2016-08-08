# securefs

`securefs` is a filesystem in userspace (FUSE) that transparently encrypts and authenticates data stored. It is particularly designed to secure data stored in the cloud.

`securefs` mounts a regular directory onto a mount point. The mount point appears as a regular filesystem, where one can read/write/create files, directories and symbolic links. The underlying directory will be automatically updated to contain the encrypted and authenticated contents.

## Motivation

From sensitive financial records to personal diaries and collection of guilty pleasures, we all have something to keep private from prying eyes. Especially when we store our files in the cloud, the company and the NSA may well get their hands upon it. The best protection we can afford ourselves is **cryptography**, the discipline developed by mathematicians and military originally to keep the national secrets.

Security, however, is often at odds with convenience, and people easily grow tired of the hassle and revert to no protection at all. Consider the case of protecting our files either locally or in the cloud: we have to encrypt the files before committing to the cloud and decrypt it every time we need to read and write. Worse still, such actions leave unencrypted traces on our hard drive. If we store data in the cloud, another issue arise: manual encryption and decryption prevent files from being synced efficiently.

`securefs` is intended to make the experience as smooth as possible so that the security and convenience do not conflict. After mounting the virtual filesystem, everything just works&#8482;.



## Install

[![Build Status](https://api.travis-ci.org/netheril96/securefs.svg?branch=master)](https://travis-ci.org/netheril96/securefs)

### Dependency: FUSE

On OS X, you need [`osxfuse`](https://osxfuse.github.io).

On Debian based Linux distro, `sudo apt-get install fuse libfuse-dev`. 

On RPM based Linux, `sudo yum install fuse fuse-devel`.

### Install with Homebrew

For OS X users, you can install `securefs` with homebrew:

```
brew install homebrew/fuse/securefs
```

### Manual Build

Run `cmake .` then `make install`. The compiler must be new enough (g++ >= 4.8, clang >= 3.4, Visual Studio >= 2015). If you encounter build errors and the compiler is new enough, try `cmake -DDISABLE_ASM=1 .` instead.

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

## Design and algorithms

See [here](docs/design.md).

## Comparison with alternatives

Compared to TrueCrypt, eCryptfs, Apple's encrypted DMG, Microsoft's BitLocker and EncFS, `securefs` has the following advantages:

### Enhanced security

#### Randomized encryption

Most alternative products employ deterministic encryption. To see why it is not secure, consider a simplified example. A military commander communicates electronically two kinds of orders, encrypted, to his subordinates. They are either "attack at dawn" or "attack at dusk". The enemy intercepts them and cannot decrypt at first. But after observing the patterns several days, where ciphertext A always precedes an attack at dawn, and ciphertext B always comes before attack at dusk, they are able to infer the meaning eventually, effectively defeating the encryption scheme. Had **randomization** been applied, in contrast, all that the enemy would obtain would look like random noise, leaving them no useful information to correlate with their observation.

#### Authenticated encryption

Authentication protects the data from being tampered. Even though the encrypted data looks like nonsense without the key to decrypt it, people have developed many methods over the years to manipulate the ciphertext to their liking without the key and decryption. Without authenticated encryption, the sensitive financial records you store may be modified and your wealth or even life may dissipate when you trust the wrong data.

If you don't care whether your data have been modified, you still have to care about authenticated encryption. This is something a lot of "military grade encryption software" gets wrong. Without integrity protection, attackers can feed a victim systematically corrupted ciphertexts and observe the behavior of the victim in handling them. That forms the basis for a family of "error oracle" side channel attacks with which the data can be decrypted. In other words, **confidentiality can hardly exist without integrity**.

### Efficient cloud sync

(This feature is also available on eCryptfs and EncFS, but not other alternatives)

Unlike alternatives, `securefs` does not preallocate the underlying storage. So you don't need to sync a, say, 4GiB disk file just in case your encrypted data will grow to that amount. If you have only 4MiB of data, then you only need to sync 4MiB (plus a small fraction of overhead).

In addition, the files are encrypted in blocks, so that binary diff update functionality (syncing only the modified part) of Dropbox, iCloud, Google Drive, etc, still works. Builtin version control of cloud services also works, albeit somewhat hard to use.


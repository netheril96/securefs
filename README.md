# securefs 0.2.0-beta

securefs is a filesystem in userspace (FUSE) that transparently encrypts and authenticates data stored. It is particularly designed to secure data stored in the cloud.

securefs mounts a regular directory onto a mount point. The mount point appears as a regular filesystem, where one can read/write/create files, directories and symbolic links. The underlying directory will be automatically updated to contain the encrypted and authenticated contents.

## Comparison

Compared to TrueCrypt, Apple's encrypted DMG or EncFS, securefs has the following advantages:

* __Randomized encryption__
* __Authenticated encryption__

Most alternative products employ deterministic encryption. To see why it is not secure, consider a simplified example. A military commander communicates electronically two kinds of orders, encrypted, to his subordinates. They are either "attack at dawn" or "attack at dusk". The enemy intercepts them and cannot decrypt at first. But after observing the patterns several days, where ciphertext A always precedes an attack at dawn, and ciphertext B always comes before attack at dusk, they are able to infer the meaning eventually, effectively defeating the encryption scheme. Had **randomization** been applied, in contrast, all that the enemy would obtain would look like random noise, leaving them no useful information to correlate with their observation.

Authentication protects the data from being tampered. Even if you don't care whether your data has been modified, you have to care about ciphertext integrity, ensured by authenticated encryption. Without integrity protection, attackers can feed a victim systematically corrupted ciphertexts and observe the behavior of the victim in handling them. That forms the basis for a family of "error oracle" side channel attacks with which the data can be decrypted. In other words, **confidentiality can hardly exist without integrity**.

## Build

[![Build Status](https://travis-ci.org/netheril96/securefs.svg)](https://travis-ci.org/netheril96/securefs)

securefs requires a Unix system, FUSE, and a recent C++ compiler. It is currently only tested on Ubuntu, Fedora and OS X.

On Debian based Linux distro, you need to install `fuse` and `libfuse-dev`. On RPM based Linux, you need `fuse` and `fuse-devel`. On OS X, you need [`osxfuse`](https://osxfuse.github.io).

Because securefs heavily uses C++11 features, a relatively new compiler and std lib is required. It has been tested with g++ 4.8 and clang++ 3.6.

Run `make securefs` to build the program. Only a single executable `securefs` will be produced. You can copy or symlink it anywhere. You can also call `strip` on it to remove debugging symbols and reduce its size. They are left in by default.

If you encounter build problems on Linux, try with `clang` instead of `gcc` (`CC=clang CXX=clang++ make securefs`).

## Basic usage

*It is recommended to disable or encrypt the swap and hibernation file. Otherwise plaintext and keys stored in the main memory may be written to disk by the OS at any time.*

```bash
securefs create ~/Secret
securefs chpass ~/Secret
securefs mount ~/Secret ~/Mount # press Ctrl-C to unmount
```

Use `securefs [verb] -h` to get detailed description of options of each command.

For example, the options of `securefs mount` include

```
   --log <path>
     Path of the log file (may contain sensitive information)

   -x,  --noxattr
     Disable built-in xattr support

   -i,  --insecure
     Disable all integrity verification (insecure mode)

   -b,  --background
     Run securefs in the background

   --stdinpass
     Read password from stdin directly (useful for piping)
```

## Design and algorithms

See [here](docs/design.md).


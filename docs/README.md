# securefs 0.10-beta

securefs is a filesystem in userspace (FUSE) that transparently encrypts and authenticates data stored. It is particularly designed to secure data stored in the cloud.

securefs mounts a regular directory onto a mount point. The mount point appears as a regular filesystem, where one can read/write/create files, directories and symbolic links. The underlying directory will be automatically updated to contain the encrypted and authenticated contents.

## Comparison

Compared to TrueCrypt, Apple's encrypted DMG or EncFS, securefs has the following advantages:

* Randomized encryption.
* Authenticated encryption.

The randomization is important because otherwise the same plaintext always maps to the same ciphertext. By observing the frequency of different ciphertext, much information can be obtained about the plaintext. If the attackers knows *a priori* the distribution of the plaintext, he/she can completely defeat the encryption scheme. The [ECB penguin](https://filippo.io/the-ecb-penguin/) is an example of the perils of deterministic encryption (although that example shows spatial patterns while here the issue is temporal patterns).

Authentication along with encryption prevents tampering of the data, a possible attack by untrusted cloud service providers (read, all cloud service providers). The integrity protection also fends off more advanced attacks such as chosen ciphertext attack.

## Build

securefs requires a Unix system, FUSE, and a decent C++ compiler. It is currently only tested on Ubuntu and OS X.

On Ubuntu, you need to install `libfuse-dev`, `clang++` and `libc++` (the default compiler and stdlib do not support many c++11 features). On OS X, you need XCode and `osxfuse`.

Run `make` to build the program. There is only a single executable `securefs` that will be produced. You can copy or symlink it anywhere.

## Basic usage

```bash
securefs create ~/Secret
securefs chpass ~/Secret
securefs mount --background ~/Secret ~/Mount
```

Use `securefs [verb] -h` to get detailed description of options of each command.


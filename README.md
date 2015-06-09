# securefs 0.10-beta

securefs is a filesystem in userspace (FUSE) that transparently encrypts and authenticates data stored. It is particularly designed to secure data stored in the cloud.

securefs mounts a regular directory onto a mount point. The mount point appears as a regular filesystem, where one can read/write/create files, directories and symbolic links. The underlying directory will be automatically updated to contain the encrypted and authenticated contents.

## Comparison

Compared to TrueCrypt, Apple's encrypted DMG or EncFS, securefs has the following advantages:

* __Randomized encryption__
* __Authenticated encryption__

The randomization is important because otherwise the same plaintext always maps to the same ciphertext. By observing the frequency of different ciphertext, much information can be obtained about the plaintext. If the attackers knows *a priori* the distribution of the plaintext, he/she can recover the plaintext. The [ECB penguin](https://filippo.io/the-ecb-penguin/) is an example of the perils of deterministic encryption (although that example shows spatial patterns while here the issue is temporal patterns).

Authentication along with encryption prevents tampering of the data, a possible attack by untrusted cloud service providers (read, all cloud service providers). The integrity protection also fends off most active attacks.

## Build

securefs requires a Unix system, FUSE, and a decent C++ compiler. It is currently only tested on Ubuntu and OS X.

On Debian based Linux distro, you need to install `fuse` and `libfuse-dev`. On RPM based Linux, you need `fuse` and `fuse-devel`. On OS X, you need [`osxfuse`](https://osxfuse.github.io).

Because securefs heavily uses C++11 features, a relatively new compiler and std lib is required. It has been tested with g++ 4.8 and clang++ 3.6.

Run `make securefs` to build the program. There is only a single executable `securefs` that will be produced. You can copy or symlink it anywhere.

## Basic usage

*It is recommended to disable or encrypt the swap and hibernation file. Otherwise plaintext and keys stored in the main memory may be written to disk by the OS at any time.*

```bash
securefs create ~/Secret
securefs chpass ~/Secret
securefs mount --background --log XXXXXX.log ~/Secret ~/Mount
```

Use `securefs [verb] -h` to get detailed description of options of each command.

For example, the options of `securefs mount` include

```
   --log <path>
     Path of the log file (may contain sensitive information

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


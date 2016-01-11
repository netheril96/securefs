# ChangeLog

## 0.2.1

Fix the critical "Too many opened files" error.

## 0.2.0

This release improves stability and performance.

* Removes most of the concurrency. The old mulithreaded codes are complicated and unverified, so the correctness was never ensured. The advantages of multithreading are also rather limited, given that no one expects I/O to be parallelizable.
* Upgrades Crypto++ from 5.6.2 to 5.6.3. This solves build problems on certain platforms, fixes some undefined behavior, and now supports hardware acceleration on OS X, with dramatic speedup if the hardware is capable.

## 0.1.0

First release.

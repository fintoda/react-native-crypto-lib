# trezor-crypto vendored sources

The `crypto/` directory in this folder is a verbatim copy of the
[`crypto/`](https://github.com/trezor/trezor-firmware/tree/main/crypto)
subtree from the [trezor-firmware](https://github.com/trezor/trezor-firmware)
monorepo. The legacy standalone repository
[`trezor/trezor-crypto`](https://github.com/trezor/trezor-crypto) is archived;
the same code lives on inside trezor-firmware and is still maintained there.

## Source

- Upstream: https://github.com/trezor/trezor-firmware
- Subdirectory: `crypto/`
- Pinned commit: `7bbda7bf74dd86b9e0810f69d72e6c7d49cb6cbc`
- License: MIT (see `crypto/LICENSE`)

## Local modifications

None. The directory is a straight copy. If a local patch ever becomes
necessary, document it here with rationale and a link to the diff.

## What we actually compile

This vendor directory contains the entire upstream `crypto/` tree (~2.5 MB)
for ease of updates and dependency completeness. The subset of files that is
actually compiled into the native library is listed explicitly in:

- `ReactNativeCryptoLib.podspec` (iOS)
- `android/CMakeLists.txt` (Android)

Adding a new algorithm = adding the corresponding `.c` file(s) to those two
build files. There is no glob over `crypto/**/*.c`, intentionally — we want
the build to fail loudly if a dependency goes missing rather than silently
pulling in unrelated code.

## Updating

Run `./update.sh <commit-sha>` to re-sync the directory to a specific upstream
commit. The script overwrites `crypto/` in place, so review the resulting diff
before committing.

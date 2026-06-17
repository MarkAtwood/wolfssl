# Building wolfSSL on Linux / macOS

## Autotools (primary build system)

From a git checkout (not a release tarball), generate the configure script first:

```bash
./autogen.sh    # requires autoconf, automake, libtool
```

Then build and test:

```bash
./configure
make
make check      # runs all tests — do this before submitting any PR
sudo make install
```

### Common configure flags

| Flag | Purpose |
|------|---------|
| `--enable-all` | Enable all features (distro build). Use this for broad testing. |
| `--enable-debug` | Debug symbols and wolfSSL debug logging |
| `--enable-opensslextra` | OpenSSL compatibility layer |
| `--enable-opensslall` | Full OpenSSL API compatibility |
| `--enable-cryptonly` | Cryptography only, no TLS |
| `--enable-dtls13` | DTLS 1.3 support |
| `--enable-mlkem` | Post-quantum ML-KEM (Kyber) |
| `--enable-mldsa` | Post-quantum ML-DSA (Dilithium) |
| `--enable-aesni` | AES-NI hardware acceleration |
| `--enable-intelasm` | All Intel assembly acceleration |
| `--enable-armasm` | ARMv8 assembly acceleration |
| `--enable-keygen` | RSA/ECC key generation |
| `--enable-certgen` | X.509 certificate generation |
| `--enable-sni` | Server Name Indication |
| `--enable-session-ticket` | TLS session tickets |
| `--enable-usersettings` | Use user_settings.h instead of autotools config |

The full list is in `./configure --help`. There are 200+ options.

### CI smoke test configurations

These are the configurations CI runs on every PR. If your change passes these, it will likely pass the full matrix:

1. `--enable-all` with AddressSanitizer
2. `--enable-all --enable-smallstack`
3. `--enable-all`
4. `--enable-openssh --enable-lighty --enable-stunnel --enable-opensslextra`
5. `--enable-psk --enable-dtls --enable-dtls13 --enable-aesccm --enable-opensslextra`
6. `--enable-opensslextra`
7. Default (no flags)
8. `--enable-cryptonly`
9. `--enable-leantls --enable-session-ticket --enable-sni --enable-opensslextra`

All smoke test builds use `--cflags=-Werror`.

## CMake (secondary)

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

For a debug build:

```bash
cmake .. -DCMAKE_BUILD_TYPE=Debug
```

Primary development and CI use autotools. CMake support is improving but autotools is the source of truth for feature configuration.

## Running Tests

```bash
make check    # full test suite
```

`make check` runs:
- `wolfcrypt/test/testwolfcrypt` — cryptographic algorithm tests
- `testsuite/testsuite.test` — TLS client/server integration
- `tests/unit.test` — API unit tests
- Script-based tests in `scripts/`

For crypto-only verification: run `wolfcrypt/test/testwolfcrypt` directly.

CI uses `bubblewrap` (`bwrap --unshare-net`) for network namespace isolation so concurrent test runs don't collide on ports.

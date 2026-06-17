# Building wolfSSL on Windows

There are several build paths for Windows. Choose the one that fits your toolchain.

## Visual Studio (recommended)

Open `wolfssl64.sln` in Visual Studio 2019 or later.

**Supported targets:** x64, Win32, ARM64
**Configurations:** Debug, Release, DLL Debug, DLL Release

### Command-line build

Open a "Developer Command Prompt for VS 2019/2022" (or run `vcvarsall.bat`), then:

```cmd
msbuild /m /p:PlatformToolset=v142 /p:Platform=x64 /p:Configuration=Release wolfssl64.sln
```

### Running tests

```cmd
:: x64
Release\x64\testsuite.exe

:: Win32
Release\Win32\testsuite.exe
```

ARM64 cross-compiles but requires an ARM64 device to run tests.

### Enabling features

The Visual Studio projects control features via preprocessor defines in the `.vcxproj` files. Two approaches:

1. **Edit preprocessor definitions** in Project Properties > C/C++ > Preprocessor Definitions. Add or remove wolfSSL feature macros (e.g., `HAVE_SNI`, `HAVE_AESGCM`, `WOLFSSL_TLS13`).

2. **Use a `user_settings.h` file** for more control. Add `WOLFSSL_USER_SETTINGS` to the preprocessor definitions and create a `user_settings.h` file. See `examples/configs/` for templates — `user_settings_all.h` is equivalent to `./configure --enable-all`.

### Additional Visual Studio solutions

| Solution | Purpose |
|----------|---------|
| `wolfcrypt/benchmark/benchmark.sln` | Crypto benchmarks |
| `wolfcrypt/benchmark/benchmark-VS2022.sln` | Crypto benchmarks (VS2022) |
| `wolfcrypt/test/test.sln` | Crypto tests only |
| `wolfcrypt/test/test-VS2022.sln` | Crypto tests only (VS2022) |
| `wrapper/CSharp/wolfSSL_CSharp.sln` | C# wrapper |

## CMake

```cmd
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

A CMake preset for VS2022 x64 is included in `CMakePresets.json`. For other architectures:

```cmd
:: Win32
cmake .. -G "Visual Studio 17 2022" -A Win32

:: ARM64
cmake .. -G "Visual Studio 17 2022" -A ARM64
```

Note: CMake integration in Visual Studio 2019 has known issues. Using the CMake GUI or command line is more reliable than the built-in VS CMake support.

## MSYS2 (autoconf on Windows)

For a Linux-like build experience on Windows using MSYS2:

```bash
# Install dependencies in the MSYS2 shell
pacman -S gcc autotools base-devel autoconf

# Build as on Linux
./autogen.sh
./configure
make
make check
```

This gives access to the full `./configure` flag set and is the closest to how CI tests the codebase.

## vcpkg

```cmd
vcpkg install wolfssl
```

## FIPS Builds

FIPS-validated builds use separate Visual Studio solutions with specific compiler and linker settings required for FIPS compliance:

| FIPS Version | Directory | Solution |
|-------------|-----------|----------|
| FIPS #2425 | `IDE/WIN/` | `wolfssl-fips.sln` |
| FIPS 140-3 | `IDE/WIN10/` | `wolfssl-fips.sln` |
| FIPS 140-3 + SRTP-KDF | `IDE/WIN-SRTP-KDF-140-3/` | `wolfssl-fips.sln` |

Each directory contains a `README.txt` with detailed instructions covering:
- Required Whole Program Optimization (WPO) settings
- ASLR and linker constraints
- In-Core Memory integrity test procedure
- DTLS variant configuration

FIPS source files are not included in the public repository. Contact support@wolfssl.com to obtain them.

## Intel SGX Enclaves

For building wolfSSL inside an Intel SGX enclave on Windows, see `IDE/WIN-SGX/ReadMe.txt`. Requires the Intel SGX SDK.

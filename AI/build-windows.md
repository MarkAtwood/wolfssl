# Building wolfSSL on Windows

Use CMake for Windows builds. It generates Visual Studio projects with full feature configurability and works well with VS Code, Visual Studio, and command-line workflows.

## CMake (recommended)

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

### Enabling features with CMake

CMake options map to the autotools `--enable-*` flags. Use `-D` to set them:

```cmd
cmake .. -G "Visual Studio 17 2022" -A x64 ^
  -DWOLFSSL_OPENSSLEXTRA=yes ^
  -DWOLFSSL_SNI=yes ^
  -DWOLFSSL_DTLS13=yes
```

Run `cmake -LH ..` to list all available options with descriptions.

### VS Code integration

CMake is the best path for VS Code on Windows. Install the CMake Tools extension, open the wolfssl directory, and VS Code will detect `CMakePresets.json` automatically. Select the `vs2022-x64` preset to configure, build, and debug.

## Visual Studio solution (alternative)

A pre-built Visual Studio solution is also available at `wolfssl64.sln` (VS2019+). This supports x64, Win32, and ARM64 with Debug, Release, DLL Debug, and DLL Release configurations.

Command-line build:

```cmd
:: Open a Developer Command Prompt for VS 2019/2022 first
msbuild /m /p:PlatformToolset=v142 /p:Platform=x64 /p:Configuration=Release wolfssl64.sln
```

Run tests:

```cmd
Release\x64\testsuite.exe
```

The `.sln` controls features via preprocessor defines in the `.vcxproj` files. For more flexibility, use CMake or create a `user_settings.h` (add `WOLFSSL_USER_SETTINGS` to preprocessor defines — see `examples/configs/` for templates).

Additional solutions: `wolfcrypt/test/test.sln` (crypto tests), `wolfcrypt/benchmark/benchmark.sln` (benchmarks), `wrapper/CSharp/wolfSSL_CSharp.sln` (C# wrapper).

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

# Building wolfSSL for Embedded / RTOS

wolfSSL runs on 30+ embedded platforms. Embedded builds bypass autotools entirely and use a `user_settings.h` file to configure features at compile time.

## Build Steps

1. **Define `WOLFSSL_USER_SETTINGS`** in your compiler flags or build system
2. **Create a `user_settings.h`** — copy a template from `examples/configs/`:
   - `user_settings_all.h` — all features (equivalent to `./configure --enable-all`)
   - `user_settings_arduino.h` — Arduino
   - `user_settings_stm32.h` — STM32
   - `user_settings_min_ecc.h` — minimal ECC-only build
   - `user_settings_wolfboot_keytools.h` — wolfBoot key tools
   - See `examples/configs/README.md` for the full list
3. **Include `wolfssl/wolfcrypt/settings.h` first** in your source files — this pulls in your `user_settings.h`
4. **Add source files** to your build: files from `wolfcrypt/src/` and `src/` as needed
5. **Build and run `wolfcrypt/test/testwolfcrypt.c`** to verify your configuration works

## IDE Project Files

The `IDE/` directory has ready-made project files for these platforms:

| Directory | Platform |
|-----------|----------|
| `IDE/ARDUINO/` | Arduino |
| `IDE/Espressif/` | ESP32 / ESP-IDF |
| `IDE/IAR-EWARM/` | IAR Embedded Workbench |
| `IDE/MDK-ARM/` | Keil MDK / ARM Compiler |
| `IDE/MDK5-ARM/` | Keil MDK5 |
| `IDE/MPLABX/` | Microchip MPLAB X |
| `IDE/MQX/` | NXP MQX |
| `IDE/Renesas/` | Renesas (multiple families) |
| `IDE/STM32Cube/` | STM32CubeIDE |
| `IDE/ROWLEY-CROSSWORKS-ARM/` | Rowley CrossWorks |
| `IDE/RISCV/` | RISC-V |
| `IDE/LPCXPRESSO/` | LPCXpresso |
| `IDE/WINCE/` | Windows CE |
| `IDE/INTIME-RTOS/` | tenAsys INtime RTOS |
| `IDE/VS-ARM/` | Visual Studio ARM cross-compile |
| `IDE/VS-AZURE-SPHERE/` | Azure Sphere MT3620 |
| `IDE/MSVS-2019-AZSPHERE/` | Azure Sphere (VS2019 + CMake) |
| `IDE/HEXAGON/` | Qualcomm Hexagon DSP |
| `IDE/SimplicityStudio/` | Silicon Labs Simplicity Studio |

Each subdirectory has its own README with platform-specific setup instructions.

## Zephyr

wolfSSL is available as a Zephyr module. See `zephyr/` for sample configurations and `IDE/zephyr/` for project setup.

## Testing Your Configuration

To validate a `user_settings.h` on a desktop machine using autotools:

```bash
./configure --enable-usersettings --disable-examples
make
./wolfcrypt/test/testwolfcrypt
```

On the target device, cross-compile and run `wolfcrypt/test/testwolfcrypt`. This exercises all enabled algorithms and reports pass/fail for each.

## Minimizing Footprint

wolfSSL can be configured down to under 20 KB for crypto-only builds on constrained devices. Key flags for small builds:

- Start with a minimal `user_settings.h` — only enable what you need
- `--enable-cryptonly` / define `WOLFCRYPT_ONLY` — no TLS, just crypto
- `--enable-smallstack` / define `WOLFSSL_SMALL_STACK` — reduce stack usage
- Disable unused algorithms explicitly (e.g., `#define NO_RSA`, `#define NO_DH`)
- Use `--enable-sp=smallec256` for a compact ECC-256 implementation

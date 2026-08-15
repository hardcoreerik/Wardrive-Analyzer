# Project Truth

Hard requirements that override convenience/defaults. Check this before
changing anything it covers.

## Never use PlatformIO for the Tab5

Build and flash exclusively via `idf.py` against a real ESP-IDF
installation. Do not build, flash, or validate hardware through
PlatformIO (`pio run`, `platformio.ini` envs, etc.) for this board.
Matches OrcSDR's own written policy (`docs/TAB5_BUILD_POLICY.md`,
same physical unit): "native ESP-IDF project... do not use PlatformIO
for development, release, or hardware validation."

Practical note: as of 2026-08-14 this project's `build/` directory is
still configured against the ESP-IDF copy bundled inside a PlatformIO
installation (`.pio-venv` / `C:\Users\hardc\.platformio\packages\
framework-espidf`) rather than a standalone ESP-IDF install (e.g.
`C:\Espressif\frameworks\esp-idf-v5.5.3`, which OrcSDR uses). The
compiled output is unaffected (same ESP-IDF version, same toolchain) --
this is about which tool invokes `idf.py`, not which compiler runs. But
the `platformio.ini` in this repo's root should be considered
deprecated/removed, and the build directory should be reconfigured
against a standalone ESP-IDF install rather than the PlatformIO-bundled
one, as follow-up hygiene work (`idf.py fullclean` + reconfigure against
a standalone install; will cost a full rebuild).

## esp_hosted MUST be pinned to 2.12.6

The ESP32-C6 coprocessor on this physical Tab5 unit (COM17, MAC
`30:ed:a0:e2:e6:95`) has **firmware 2.12.6 fixed in flash**. The host-side
`espressif/esp_hosted` component version must match it. This is not
negotiable/convenience-driven — OrcSDR (`F:\Ai\OrcSDR-idf`, same physical
unit) proves 2.12.x is the correct, working pairing on this exact
hardware.

**Status update (2026-08-14, later same day)**: exact `"2.12.6"` pin
(not `^2.12.6`, which resolves to 2.12.12) plus manual SDIO pin config
(no Tab5 board preset exists in exact 2.12.6 -- see manual pins in
`sdkconfig.defaults`) plus OrcSDR-derived stability settings
(`ESP_HOSTED_DFLT_TASK_FROM_SPIRAM=y`, `ESP_HOSTED_USE_MEMPOOL=y`,
smaller SDIO TX/RX queues, `CONFIG_FREERTOS_HZ=1000`) together **fix the
`assert failed: esp_startup_start_app` boot crash** -- confirmed on
hardware, boots clean to `system ready`, M5GFX display works too.

**New problem, not yet fixed**: with this exact config, WiFi itself now
fails to come up: `H_SDIO_DRV: card init failed` /
`wifi: esp_wifi_init failed: ESP_FAIL`. The crash is gone but the SDIO
link to the C6 doesn't establish. Likely something in the manually-typed
pin/reset config is still off (unlike 2.12.12+, exact 2.12.6 has no
Tab5 board preset to cross-check against) -- needs more debugging before
this is actually a complete fix. Do not consider this resolved until
WiFi is confirmed working end-to-end (scan returning real APs) on this
exact 2.12.6 pin, matching what was already proven working on `"*"`
(3.0.6).

**Do not silently leave this on `"*"`/3.0.6 as a permanent fix.** The
version-mismatch warning it logs against the real 2.12.6 coprocessor
firmware is a symptom of using the wrong package, not a cosmetic
non-issue -- keep chasing the 2.12.x boot crash until it's resolved.

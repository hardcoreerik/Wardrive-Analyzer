# OrcAlyzer Tab5 Firmware (ESP-IDF)

M5Stack Tab5 (ESP32-P4 + ESP32-C6) field firmware for OrcAlyzer (formerly
Wardrive Analyzer). Part of the OrcAlyzer monorepo — see the root
[README](../README.md) for how this fits alongside the desktop app and
`android-app/`.

**Build/flash exclusively via `idf.py` (see `tools/build-tab5-idf.ps1`) —
never PlatformIO.** See `project_truth.md` for why. `platformio.ini` and
PlatformIO-generated `sdkconfig.*` files are gitignored so they can't
slip back in.

Targets **ESP-IDF-first**: the official Tab5 BSP component
(`espressif/m5stack_tab5`, vendored + patched under `components/`),
M5GFX for display/touch, LVGL for UI, `esp_wifi_remote`/`esp_hosted` for
WiFi over the P4↔C6 hosted link.

## Status (2026-08-14)

- **Display + touch: confirmed working on real hardware** — not just
  boot logs, direct visual/touch confirmation. Screen renders at
  1280x720, buttons respond to touch, rotation works. Driven by M5GFX
  (see "Display via M5GFX" below); the stock esp-bsp path never actually
  drove this unit's screen (it assumes an ILI9881C+GT911 panel, this
  unit has the newer combined ST7123 TDDI chip).
- **UI sized for this panel's actual density**: 5" at 1280x720 is
  ~294 PPI, higher than the default LVGL font/button sizes assumed.
  Fonts bumped to Montserrat 24 (body) / 28 (buttons) / 32 (headers);
  nav buttons resized to 400x110 (reference: OrcSDR's proven 500x120 on
  this same physical unit). Confirm current sizing still reads well
  before assuming this is final — display density work tends to need a
  second pass once more screens exist.
- **WiFi: broken on the currently-required exact `esp_hosted` pin.**
  This unit's C6 coprocessor firmware is fixed at **2.12.6** (can only
  be changed via M5Burner's official firmware or JTAG/serial — not
  something this project touches), so the host-side `esp_hosted`
  component must match exactly. That exact pin fixes an earlier boot
  crash (see project_truth.md) but the SDIO link to the C6 currently
  fails to establish (`H_SDIO_DRV: card init failed`,
  `esp_wifi_init failed: ESP_FAIL`). Manually-typed SDIO pin config is
  the suspect (2.12.6 predates the auto board-preset later 2.12.x
  patches added) — **do not consider WiFi working until this is fixed
  and a real scan returns real APs on the 2.12.6 pin**. Full detail and
  current state in `project_truth.md`.

## Reference: OrcSDR

`F:\Ai\OrcSDR-idf` (GitHub: `hardcoreerik/OrcSDR`) targets the **same
physical Tab5 unit** — confirmed by matching device identity/MAC. It has
independently-proven working display, touch, and WiFi (via Arduino +
M5Unified/M5GFX as ESP-IDF components, not PlatformIO, not a pure
Arduino-IDE build). Check it before re-deriving Tab5 hardware bring-up
details from scratch — several of this firmware's fixes (SDIO pin map,
exact esp_hosted version, ST7123 chip ID, build tooling) came directly
from there. `docs/TAB5_BUILD_POLICY.md` and `docs/M5TAB5_VALIDATION_REPORT.md`
in that repo are the most load-bearing references.

## Display via M5GFX

The vendored BSP (`components/m5stack_tab5`, pinned at esp-bsp commit
`4b3f542`) has no ST7123 *panel* driver — the touch side got a fallback
patch (`esp_lcd_touch_st7123`, see `components/m5stack_tab5/src/m5stack_tab5.c`),
but there was never a real fix for the display panel itself until M5GFX
was ported in.

`espressif/m5stack/M5GFX` v0.2.26 is a git dependency in
`main/idf_component.yml` (no Espressif-registry namespace for it, hence
`git:` not `version:` alone) — consumable as a pure ESP-IDF component,
no Arduino framework switch needed (confirmed via its own
`idf_component.yml`/`CMakeLists.txt`). It ships a real `Panel_ST7123` +
`Touch_ST7123` under `src/lgfx/v1/platforms/esp32p4/`, with Tab5
auto-detection that probes I2C address `0x55` — the same address this
project's own `touch::probe()` found ST7123 at independently.

`main/display.cpp` drives the panel through M5GFX and bridges it to LVGL
manually (`lv_display_create` + a `pushImage`-based flush callback + a
dedicated pump task calling `lv_timer_handler()`), since `esp_lvgl_port`
only knows how to drive a raw `esp_lcd_panel_handle_t`, not M5GFX's own
panel abstraction. `display.h`'s public API is unchanged, so `ui.cpp`
needed no interface changes. `main/touch.cpp` reads through an
`lv_indev_t` registered by `display.cpp`.

Known loose end: `touch::probe()`'s own diagnostic I2C scan reads
`I2C=none` right after M5GFX's init, even on a boot where M5GFX itself
successfully detected and is driving the ST7123 panel+touch. Likely
M5GFX's self-contained I2C+IO-expander bring-up (GPIO 31/32) leaves the
bus in a state the BSP's own `bsp_i2c_init()`-based probe can't see
afterward. Diagnostic-only as far as confirmed — doesn't appear to
affect real touch input, which works.

## WiFi Architecture

Tab5's ESP32-P4 has no native radio; WiFi lives on the on-board ESP32-C6,
bridged over SDIO. `main/idf_component.yml` pins `espressif/esp_hosted`
to exactly `2.12.6` (see project_truth.md for why the version must match
exactly) and `espressif/esp_wifi_remote`; application code just includes
`esp_wifi.h` and uses the normal scan API (`main/wifi.cpp`) — the
component transparently routes calls to the C6. Exact 2.12.6 has no
Tab5 board auto-preset, so SDIO pins/reset polarity are set manually in
`sdkconfig.defaults` (CLK=12 CMD=13 D0=11 D1=10 D2=9 D3=8 RESET=15,
reset active-low) — **currently not yet getting the SDIO link to
establish; see Status above and project_truth.md.**

Tab5 has 16MB flash; the WiFi/mbedTLS/lwIP stack doesn't fit the default
1MB single-app partition, so the project uses a custom `partitions.csv`
with 3MB OTA-capable app slots + a 2MB SPIFFS storage partition. No OTA
update flow is wired yet (no `esp_ota_mark_app_valid_cancel_rollback()`
call) — add one before shipping real OTA.

## What Else Is Here

- I2C diagnostics for GT911/ST7123 address probing (`touch::probe()`).
- Status bar with WiFi/SD/battery/heap/PSRAM summaries.
- **OUI vendor lookup** on the WiFi Scan screen — BSSIDs tagged with a
  vendor name from a small seed table (`main/oui.cpp`). Not exhaustive;
  the desktop app's `oui.csv` (repo root) may be a better/fuller source
  to pull from than the current hand-picked seed list — worth checking
  whether they should be unified into one shared source.
- **Companion Link**: a real HTTP client (`main/companion.h`/`companion.cpp`),
  not a stub. Does mDNS discovery of `_wardrive._tcp`, then `GET /health`
  and `GET /sessions` on whatever it finds; the UI shows live status and
  session summaries. The `/sessions` JSON schema
  (`[{id, name, started_at, network_count}]`) is a best-guess contract —
  the desktop app doesn't have a matching endpoint yet to confirm
  against. Now that this firmware lives in the same repo as the desktop
  app, defining that contract together (rather than guessing from the
  firmware side) is worth doing before it's relied on.
- `main.cpp` doesn't block forever on any single peripheral failure —
  display/touch/WiFi each degrade independently. Also the right shape
  for a possible future headless fleet-hub role (Tab5 as hub, smaller
  ESP32 nodes doing capture work) if that direction gets picked up.
- `Serial Bridge` screen is still an intentional stub (no live control).

## Build (ESP-IDF)

```powershell
.\tools\build-tab5-idf.ps1
```

## Flash (COM17)

```powershell
.\tools\build-tab5-idf.ps1 -Flash -Port COM17
```

Both use the ESP-IDF copy bundled with this machine's PlatformIO
install (`.pio-venv`) as the actual toolchain — not PlatformIO itself,
just its bundled ESP-IDF, since that's what this repo's `build/`
directory is currently configured against. Migrating to a fully
standalone ESP-IDF install (matching OrcSDR's setup) is tracked as
follow-up hygiene work in `project_truth.md`.

## Notes

- Tab5 hardware revisions may use ILI9881C+GT911 (older) or ST7123 (this
  unit; newer, integrated display-touch). `bsp_touch_new()` tries GT911
  first, falls back to ST7123.
- `sdkconfig.defaults` is aligned to M5 Tab5 user-demo hardware defaults
  (flash/QIO/PSRAM/cache), with one compatibility override for ESP32-P4
  rev 1.x units.

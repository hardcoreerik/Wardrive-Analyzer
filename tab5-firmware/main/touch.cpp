#include "touch.h"

#include <stdio.h>

#include "bsp/esp-bsp.h"
#include "display.h"
#include "esp_log.h"
#include "esp_timer.h"

namespace touch {
namespace {

static const char *kTag = "touch";

constexpr uint8_t kGt911AddrPrimary = 0x5D;
constexpr uint8_t kGt911AddrBackup = 0x14;
constexpr uint8_t kSt7123AddrPrimary = 0x55;
constexpr uint8_t kSt7123AddrBackup = 0x56;

TouchState s_state;
ProbeResult s_probe;
lv_indev_t *s_indev = nullptr;

void record_addr(uint8_t address) {
    if (s_probe.count < static_cast<uint8_t>(sizeof(s_probe.responding))) {
        s_probe.responding[s_probe.count++] = address;
    }
}

bool ping_addr(i2c_master_bus_handle_t i2c, uint8_t address) {
    return (i2c != nullptr) && (i2c_master_probe(i2c, address, 10) == ESP_OK);
}

}  // namespace

bool begin() {
    s_probe = {};
    bsp_i2c_init();
    i2c_master_bus_handle_t i2c = bsp_i2c_get_handle();

    for (uint8_t addr = 0x08; addr < 0x78; ++addr) {
        if (ping_addr(i2c, addr)) {
            record_addr(addr);
        }
    }

    s_probe.gt911_seen = ping_addr(i2c, kGt911AddrPrimary) || ping_addr(i2c, kGt911AddrBackup);
    s_probe.st7123_seen = ping_addr(i2c, kSt7123AddrPrimary) || ping_addr(i2c, kSt7123AddrBackup);

    s_indev = display::input_device();
    ESP_LOGI(kTag, "%s", probe_summary().c_str());
    return s_indev != nullptr;
}

void poll() {
    if (s_indev == nullptr) {
        s_indev = display::input_device();
        if (s_indev == nullptr) {
            return;
        }
    }

    lv_point_t point = {0, 0};
    lv_indev_get_point(s_indev, &point);
    const lv_indev_state_t indev_state = lv_indev_get_state(s_indev);
    const bool pressed = (indev_state == LV_INDEV_STATE_PRESSED) || (indev_state == LV_INDEV_STATE_PR);

    if (pressed) {
        s_state.x = point.x;
        s_state.y = point.y;
    }
    if (pressed != s_state.pressed) {
        s_state.last_change_ms = static_cast<uint32_t>(esp_timer_get_time() / 1000ULL);
    }
    s_state.pressed = pressed;
}

TouchState state() {
    return s_state;
}

ProbeResult probe() {
    return s_probe;
}

std::string probe_summary() {
    char line[240];
    int used = snprintf(
        line,
        sizeof(line),
        "Touch probe GT911=%s ST7123=%s I2C=",
        s_probe.gt911_seen ? "seen" : "not-seen",
        s_probe.st7123_seen ? "seen" : "not-seen"
    );

    if (s_probe.count == 0) {
        snprintf(line + used, sizeof(line) - used, "none");
    } else {
        for (uint8_t i = 0; i < s_probe.count && used < static_cast<int>(sizeof(line)); ++i) {
            used += snprintf(
                line + used,
                sizeof(line) - used,
                "%s0x%02X",
                (i == 0) ? "" : ",",
                s_probe.responding[i]
            );
        }
    }

    return std::string(line);
}

}  // namespace touch

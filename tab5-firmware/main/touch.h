#pragma once

#include <stdint.h>
#include <string>

namespace touch {

struct TouchState {
    bool pressed = false;
    int16_t x = 0;
    int16_t y = 0;
    uint32_t last_change_ms = 0;
};

struct ProbeResult {
    bool gt911_seen = false;
    bool st7123_seen = false;
    uint8_t responding[16] = {};
    uint8_t count = 0;
};

bool begin();
void poll();
TouchState state();
ProbeResult probe();
std::string probe_summary();

}  // namespace touch

#pragma once

#include <stdint.h>

#include <string>
#include <vector>

namespace wifi {

struct AccessPoint {
    std::string ssid;
    std::string bssid;
    int8_t rssi = 0;
    uint8_t channel = 0;
    bool secure = true;
};

enum class ScanState {
    Idle,
    Scanning,
    Done,
    Failed,
};

// Brings up the P4<->C6 hosted link (esp_wifi_remote) and starts the STA
// driver. Returns false if the coprocessor transport never comes up; callers
// should treat WiFi as unavailable rather than retry in a tight loop.
bool begin();

bool available();
void start_scan();
ScanState scan_state();
std::vector<AccessPoint> results();
std::string status_text();

}  // namespace wifi

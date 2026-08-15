#pragma once

#include <stdint.h>
#include <string>

namespace utils {

struct SystemStatus {
    std::string wifi;
    std::string sd_card;
    std::string battery;
    std::string heap;
    std::string psram;
    std::string uptime;
};

struct CompanionContract {
    const char *service_name;
    const char *mdns_type;
    const char *health_path;
    const char *sessions_path;
    uint16_t default_port;
};

struct SerialBridgeContract {
    const char *label;
    uint32_t baud;
    const char *line_ending;
};

void begin();
SystemStatus read_status();
std::string system_info_text();
bool sd_card_available();

const CompanionContract &companion_contract();
const SerialBridgeContract &serial_bridge_contract();

}  // namespace utils

#pragma once

#include <stdint.h>

#include <string>
#include <vector>

namespace companion {

struct SessionSummary {
    std::string id;
    std::string name;
    std::string started_at;
    uint32_t network_count = 0;
};

enum class LinkState {
    Idle,
    Discovering,
    Connected,
    Unreachable,
    NotFound,
};

// Requires wifi::available() -- mDNS needs an up netif to query on.
void begin();

// Kicks off mDNS discovery + a /health + /sessions fetch on a background
// task. No-op if a discovery is already in flight.
void start_discovery();

LinkState state();
std::string host();  // "ip:port" once resolved, empty otherwise
std::vector<SessionSummary> sessions();
std::string status_text();

}  // namespace companion

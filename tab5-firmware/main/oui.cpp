#include "oui.h"

#include <algorithm>
#include <cctype>
#include <unordered_map>

namespace oui {
namespace {

// Seed table of common OUI prefixes -> vendor name. Not exhaustive (the
// full IEEE MA-L registry is ~50k entries / several MB) -- covers the
// vendors most likely to show up wardriving: APs/routers, phones/laptops,
// and other ESP32 devices. Same approach NEONDRIVE's CYDCompanion app
// takes with its bundled oui.csv seed list. Extend as needed, or load a
// fuller CSV from SD card later (utils::sd_card_available() already
// exists as a gate for that).
const std::unordered_map<std::string, const char *> kSeedTable = {
    {"24:0A:C4", "Espressif"},
    {"30:AE:A4", "Espressif"},
    {"3C:71:BF", "Espressif"},
    {"84:CC:A8", "Espressif"},
    {"A4:CF:12", "Espressif"},
    {"EC:FA:BC", "Espressif"},
    {"CC:50:E3", "Espressif"},
    {"B8:27:EB", "Raspberry Pi Foundation"},
    {"DC:A6:32", "Raspberry Pi Foundation"},
    {"D8:3A:DD", "Raspberry Pi Foundation"},
    {"E4:5F:01", "Raspberry Pi Foundation"},
    {"50:C7:BF", "TP-Link"},
    {"EC:08:6B", "TP-Link"},
    {"C4:6E:1F", "TP-Link"},
    {"A0:40:A0", "Netgear"},
    {"20:E5:2A", "Netgear"},
    {"84:1B:5E", "Netgear"},
    {"00:1E:58", "D-Link"},
    {"C8:D3:A3", "D-Link"},
    {"24:A4:3C", "Ubiquiti"},
    {"78:8A:20", "Ubiquiti"},
    {"DC:9F:DB", "Ubiquiti"},
    {"F0:9F:C2", "Ubiquiti"},
    {"00:1B:21", "Intel"},
    {"A4:34:D9", "Intel"},
    {"54:60:09", "Google/Nest"},
    {"F4:F5:D8", "Google/Nest"},
    {"1C:F2:9A", "Google/Nest"},
    {"74:C2:46", "Amazon"},
    {"F0:27:2D", "Amazon"},
    {"68:37:E9", "Amazon"},
    {"00:0E:58", "Sonos"},
    {"5C:AA:FD", "Sonos"},
    {"F0:18:98", "Apple"},
    {"DC:A9:04", "Apple"},
    {"3C:15:C2", "Apple"},
    {"00:1B:63", "Apple"},
    {"5C:0A:5B", "Samsung"},
    {"00:12:FB", "Samsung"},
};

std::string normalize_oui(const std::string &bssid) {
    if (bssid.size() < 8) {
        return "";
    }
    std::string prefix = bssid.substr(0, 8);
    std::transform(prefix.begin(), prefix.end(), prefix.begin(),
                    [](unsigned char c) { return std::toupper(c); });
    return prefix;
}

}  // namespace

std::string lookup_vendor(const std::string &bssid) {
    const std::string prefix = normalize_oui(bssid);
    if (prefix.empty()) {
        return "";
    }
    const auto it = kSeedTable.find(prefix);
    return (it != kSeedTable.end()) ? it->second : "";
}

}  // namespace oui

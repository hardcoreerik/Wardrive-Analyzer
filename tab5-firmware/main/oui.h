#pragma once

#include <string>

namespace oui {

// Looks up the vendor for a "XX:XX:XX:XX:XX:XX" BSSID by its 3-byte OUI
// prefix. Returns an empty string if the prefix isn't in the seed table.
std::string lookup_vendor(const std::string &bssid);

}  // namespace oui

#include "utils.h"

#include <stdio.h>

#include "bsp/esp-bsp.h"
#include "esp_chip_info.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "wifi.h"

namespace utils {
namespace {

static const char *kTag = "utils";

bool s_sd_mounted = false;

const CompanionContract kCompanion = {
    "Wardrive Analyzer Desktop",
    "_wardrive._tcp",
    "/health",
    "/sessions",
    8765,
};

const SerialBridgeContract kSerialBridge = {
    "Marauder-style USB serial bridge",
    115200,
    "\\r\\n",
};

std::string bytes_text(uint64_t bytes) {
    char out[48];
    if (bytes >= 1024ULL * 1024ULL) {
        snprintf(out, sizeof(out), "%.1f MB", static_cast<double>(bytes) / 1048576.0);
    } else if (bytes >= 1024ULL) {
        snprintf(out, sizeof(out), "%.1f KB", static_cast<double>(bytes) / 1024.0);
    } else {
        snprintf(out, sizeof(out), "%llu B", static_cast<unsigned long long>(bytes));
    }
    return std::string(out);
}

std::string chip_text() {
    esp_chip_info_t info;
    esp_chip_info(&info);
    char out[96];
    snprintf(
        out,
        sizeof(out),
        "ESP32-P4 rev %u cores=%u features=0x%08lx",
        info.revision,
        info.cores,
        static_cast<unsigned long>(info.features)
    );
    return std::string(out);
}

}  // namespace

void begin() {
    // Power up the Tab5 Wi-Fi coprocessor path for future companion networking.
    bsp_feature_enable(BSP_FEATURE_WIFI, true);

    const esp_err_t sd_err = bsp_sdcard_mount();
    s_sd_mounted = (sd_err == ESP_OK);
    if (!s_sd_mounted) {
        ESP_LOGW(kTag, "SD mount skipped or failed: %s", esp_err_to_name(sd_err));
    }
}

SystemStatus read_status() {
    SystemStatus status;

    status.wifi = wifi::status_text();
    status.sd_card = s_sd_mounted ? "SD mounted" : "SD missing";

#if BSP_CAPS_BAT
    status.battery = "Battery telemetry ready";
#else
    status.battery = "Battery telemetry unavailable on current BSP";
#endif

    status.heap = "Heap " + bytes_text(esp_get_free_heap_size());
    status.psram = "PSRAM " + bytes_text(heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

    const uint64_t uptime_s = static_cast<uint64_t>(esp_timer_get_time() / 1000000ULL);
    status.uptime = std::to_string(static_cast<unsigned long long>(uptime_s)) + "s";
    return status;
}

std::string system_info_text() {
    const SystemStatus status = read_status();

    std::string out;
    out.reserve(1024);
    out += "Wardrive Analyzer Tab5 (ESP-IDF foundation)\n\n";
    out += chip_text();
    out += "\n";
    out += "IDF: ";
    out += esp_get_idf_version();
    out += "\n";
    out += status.heap + "\n";
    out += "Min heap " + bytes_text(esp_get_minimum_free_heap_size()) + "\n";
    out += status.psram + "\n";
    out += "PSRAM total (runtime) unavailable in current toolchain\n";
    out += status.sd_card + "\n";
    out += status.battery + "\n";
    out += status.wifi + "\n";
    out += "Uptime " + status.uptime + "\n\n";
    out += "PC sync contract:\n";
    out += "  mDNS: " + std::string(kCompanion.mdns_type) + "\n";
    out += "  Port: " + std::to_string(kCompanion.default_port) + "\n";
    out += "  Health: " + std::string(kCompanion.health_path) + "\n";
    out += "  Sessions: " + std::string(kCompanion.sessions_path) + "\n\n";
    out += "Serial bridge contract:\n";
    out += "  Baud: " + std::to_string(kSerialBridge.baud) + "\n";
    out += "  Line ending: " + std::string(kSerialBridge.line_ending) + "\n";
    return out;
}

bool sd_card_available() {
    return s_sd_mounted;
}

const CompanionContract &companion_contract() {
    return kCompanion;
}

const SerialBridgeContract &serial_bridge_contract() {
    return kSerialBridge;
}

}  // namespace utils

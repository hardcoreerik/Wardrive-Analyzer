#include "wifi.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs_flash.h"

namespace wifi {
namespace {

static const char *kTag = "wifi";
constexpr uint16_t kMaxRecords = 40;

bool s_available = false;
ScanState s_state = ScanState::Idle;
std::vector<AccessPoint> s_results;
SemaphoreHandle_t s_mutex = nullptr;

void collect_scan_results() {
    uint16_t count = kMaxRecords;
    static wifi_ap_record_t records[kMaxRecords];
    const esp_err_t err = esp_wifi_scan_get_ap_records(&count, records);

    std::vector<AccessPoint> parsed;
    if (err == ESP_OK) {
        parsed.reserve(count);
        for (uint16_t i = 0; i < count; ++i) {
            AccessPoint ap;
            ap.ssid = reinterpret_cast<const char *>(records[i].ssid);
            char bssid[18];
            snprintf(
                bssid, sizeof(bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
                records[i].bssid[0], records[i].bssid[1], records[i].bssid[2],
                records[i].bssid[3], records[i].bssid[4], records[i].bssid[5]
            );
            ap.bssid = bssid;
            ap.rssi = records[i].rssi;
            ap.channel = records[i].primary;
            ap.secure = records[i].authmode != WIFI_AUTH_OPEN;
            parsed.push_back(std::move(ap));
        }
    } else {
        ESP_LOGW(kTag, "scan_get_ap_records failed: %s", esp_err_to_name(err));
    }

    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        s_results = std::move(parsed);
        s_state = (err == ESP_OK) ? ScanState::Done : ScanState::Failed;
        xSemaphoreGive(s_mutex);
    }
}

void on_wifi_event(void *, esp_event_base_t, int32_t event_id, void *) {
    if (event_id == WIFI_EVENT_SCAN_DONE) {
        collect_scan_results();
    }
}

}  // namespace

bool begin() {
    s_mutex = xSemaphoreCreateMutex();

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "nvs_flash_init failed: %s", esp_err_to_name(err));
        return false;
    }

    err = esp_netif_init();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(kTag, "esp_netif_init failed: %s", esp_err_to_name(err));
        return false;
    }

    err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(kTag, "esp_event_loop_create_default failed: %s", esp_err_to_name(err));
        return false;
    }

    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    err = esp_wifi_init(&cfg);
    if (err != ESP_OK) {
        // Most likely failure point on Tab5: the P4<->C6 hosted/SDIO
        // transport never came up, so esp_wifi_remote has nothing to talk
        // to. Report unavailable instead of retrying.
        ESP_LOGE(kTag, "esp_wifi_init failed: %s", esp_err_to_name(err));
        return false;
    }

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &on_wifi_event, nullptr, nullptr
    ));

    err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "esp_wifi_set_mode failed: %s", esp_err_to_name(err));
        return false;
    }

    err = esp_wifi_start();
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "esp_wifi_start failed: %s", esp_err_to_name(err));
        return false;
    }

    s_available = true;
    ESP_LOGI(kTag, "wifi remote link up, STA mode ready");
    return true;
}

bool available() {
    return s_available;
}

void start_scan() {
    if (!s_available) {
        return;
    }
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        if (s_state == ScanState::Scanning) {
            xSemaphoreGive(s_mutex);
            return;
        }
        s_state = ScanState::Scanning;
        xSemaphoreGive(s_mutex);
    }

    wifi_scan_config_t scan_cfg = {};
    scan_cfg.show_hidden = true;
    const esp_err_t err = esp_wifi_scan_start(&scan_cfg, false);
    if (err != ESP_OK) {
        ESP_LOGW(kTag, "scan_start failed: %s", esp_err_to_name(err));
        if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
            s_state = ScanState::Failed;
            xSemaphoreGive(s_mutex);
        }
    }
}

ScanState scan_state() {
    ScanState state = ScanState::Idle;
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        state = s_state;
        xSemaphoreGive(s_mutex);
    }
    return state;
}

std::vector<AccessPoint> results() {
    std::vector<AccessPoint> copy;
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        copy = s_results;
        xSemaphoreGive(s_mutex);
    }
    return copy;
}

std::string status_text() {
    if (!s_available) {
        return "WiFi unavailable (C6 hosted link down)";
    }
    switch (scan_state()) {
        case ScanState::Scanning:
            return "WiFi scanning...";
        case ScanState::Done:
            return "WiFi scan complete";
        case ScanState::Failed:
            return "WiFi scan failed";
        case ScanState::Idle:
        default:
            return "WiFi ready";
    }
}

}  // namespace wifi

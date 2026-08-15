#include "companion.h"

#include <cstring>

#include "cJSON.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "mdns.h"
#include "utils.h"
#include "wifi.h"

namespace companion {
namespace {

static const char *kTag = "companion";
constexpr uint32_t kMdnsQueryTimeoutMs = 3000;
constexpr int kHttpTimeoutMs = 3000;
constexpr size_t kMaxHttpBody = 8192;

SemaphoreHandle_t s_mutex = nullptr;
LinkState s_state = LinkState::Idle;
std::string s_host;
std::vector<SessionSummary> s_sessions;
bool s_discovery_running = false;

void set_state(LinkState state) {
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        s_state = state;
        xSemaphoreGive(s_mutex);
    }
}

// Fetches a URL into a caller-provided buffer via a single-shot blocking
// GET. Returns the HTTP status code, or -1 on transport-level failure.
// Truncates silently past kMaxHttpBody -- session lists are expected to
// be small summaries, not full capture dumps.
int http_get(const std::string &url, std::string &out_body) {
    esp_http_client_config_t cfg = {};
    cfg.url = url.c_str();
    cfg.timeout_ms = kHttpTimeoutMs;
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (client == nullptr) {
        return -1;
    }

    const esp_err_t open_err = esp_http_client_open(client, 0);
    if (open_err != ESP_OK) {
        esp_http_client_cleanup(client);
        return -1;
    }

    esp_http_client_fetch_headers(client);
    static char buf[kMaxHttpBody];
    int total = 0;
    while (total < static_cast<int>(sizeof(buf)) - 1) {
        const int read = esp_http_client_read(client, buf + total, sizeof(buf) - 1 - total);
        if (read <= 0) {
            break;
        }
        total += read;
    }
    buf[total] = '\0';
    out_body.assign(buf, static_cast<size_t>(total));

    const int status = esp_http_client_get_status_code(client);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return status;
}

// Expected /sessions response: a JSON array of
// {"id": str, "name": str, "started_at": str, "network_count": int}.
// This is our own guess at the contract -- the desktop app is still
// under development, so adjust field names here once it's finalized.
std::vector<SessionSummary> parse_sessions(const std::string &body) {
    std::vector<SessionSummary> out;
    cJSON *root = cJSON_Parse(body.c_str());
    if (root == nullptr || !cJSON_IsArray(root)) {
        if (root) {
            cJSON_Delete(root);
        }
        return out;
    }

    cJSON *item;
    cJSON_ArrayForEach(item, root) {
        SessionSummary s;
        const cJSON *id = cJSON_GetObjectItemCaseSensitive(item, "id");
        const cJSON *name = cJSON_GetObjectItemCaseSensitive(item, "name");
        const cJSON *started = cJSON_GetObjectItemCaseSensitive(item, "started_at");
        const cJSON *count = cJSON_GetObjectItemCaseSensitive(item, "network_count");
        if (cJSON_IsString(id)) {
            s.id = id->valuestring;
        }
        if (cJSON_IsString(name)) {
            s.name = name->valuestring;
        }
        if (cJSON_IsString(started)) {
            s.started_at = started->valuestring;
        }
        if (cJSON_IsNumber(count)) {
            s.network_count = static_cast<uint32_t>(count->valuedouble);
        }
        out.push_back(std::move(s));
    }
    cJSON_Delete(root);
    return out;
}

void discovery_task(void *) {
    set_state(LinkState::Discovering);

    const utils::CompanionContract &contract = utils::companion_contract();

    // mdns_type is stored as "_wardrive._tcp" -- split on the dot for the
    // query call, which wants service/proto separately.
    const std::string type(contract.mdns_type);
    const size_t dot = type.find('.');
    const std::string service = (dot != std::string::npos) ? type.substr(0, dot) : type;
    const std::string proto = (dot != std::string::npos) ? type.substr(dot + 1) : "_tcp";

    mdns_result_t *results = nullptr;
    const esp_err_t err = mdns_query_ptr(service.c_str(), proto.c_str(), kMdnsQueryTimeoutMs, 1, &results);

    std::string host_port;
    if (err == ESP_OK && results != nullptr) {
        const mdns_result_t *r = results;
        char ip_str[16] = {};
        if (r->addr != nullptr) {
            esp_ip4addr_ntoa(&r->addr->addr.u_addr.ip4, ip_str, sizeof(ip_str));
            host_port = std::string(ip_str) + ":" + std::to_string(r->port);
        }
        mdns_query_results_free(results);
    }

    if (host_port.empty()) {
        ESP_LOGW(kTag, "mDNS discovery found no %s%s instance", service.c_str(), proto.c_str());
        set_state(LinkState::NotFound);
        s_discovery_running = false;
        vTaskDelete(nullptr);
        return;
    }

    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        s_host = host_port;
        xSemaphoreGive(s_mutex);
    }

    const std::string health_url = "http://" + host_port + std::string(contract.health_path);
    std::string body;
    const int health_status = http_get(health_url, body);
    if (health_status != 200) {
        ESP_LOGW(kTag, "health check failed (status=%d) at %s", health_status, health_url.c_str());
        set_state(LinkState::Unreachable);
        s_discovery_running = false;
        vTaskDelete(nullptr);
        return;
    }

    const std::string sessions_url = "http://" + host_port + std::string(contract.sessions_path);
    body.clear();
    const int sessions_status = http_get(sessions_url, body);
    std::vector<SessionSummary> parsed;
    if (sessions_status == 200) {
        parsed = parse_sessions(body);
    } else {
        ESP_LOGW(kTag, "sessions fetch failed (status=%d)", sessions_status);
    }

    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        s_sessions = std::move(parsed);
        xSemaphoreGive(s_mutex);
    }
    set_state(LinkState::Connected);

    s_discovery_running = false;
    vTaskDelete(nullptr);
}

}  // namespace

void begin() {
    s_mutex = xSemaphoreCreateMutex();
    if (!wifi::available()) {
        return;
    }
    const esp_err_t err = mdns_init();
    if (err != ESP_OK) {
        ESP_LOGW(kTag, "mdns_init failed: %s", esp_err_to_name(err));
    }
}

void start_discovery() {
    if (!wifi::available() || s_discovery_running) {
        return;
    }
    s_discovery_running = true;
    xTaskCreate(discovery_task, "companion_disc", 6144, nullptr, tskIDLE_PRIORITY + 1, nullptr);
}

LinkState state() {
    LinkState result = LinkState::Idle;
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        result = s_state;
        xSemaphoreGive(s_mutex);
    }
    return result;
}

std::string host() {
    std::string result;
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        result = s_host;
        xSemaphoreGive(s_mutex);
    }
    return result;
}

std::vector<SessionSummary> sessions() {
    std::vector<SessionSummary> result;
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        result = s_sessions;
        xSemaphoreGive(s_mutex);
    }
    return result;
}

std::string status_text() {
    if (!wifi::available()) {
        return "Companion Link needs WiFi";
    }
    switch (state()) {
        case LinkState::Discovering:
            return "Discovering desktop...";
        case LinkState::Connected:
            return "Connected: " + host();
        case LinkState::Unreachable:
            return "Found " + host() + " but it's not responding";
        case LinkState::NotFound:
            return "No Wardrive Desktop found on this network";
        case LinkState::Idle:
        default:
            return "Not connected";
    }
}

}  // namespace companion

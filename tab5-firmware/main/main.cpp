#include "companion.h"
#include "display.h"
#include "touch.h"
#include "ui.h"
#include "utils.h"
#include "wifi.h"

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

extern "C" void app_main(void) {
    static const char *kTag = "main";
    ESP_LOGI(kTag, "Wardrive Analyzer Tab5 ESP-IDF foundation boot");

    // Display is one peripheral among several -- a GT911/panel fault
    // shouldn't take down WiFi, SD, or anything else this device can still
    // usefully do (e.g. acting as a headless scan node in a fleet). Only
    // ui::begin()/tick() actually require a working display.
    const bool display_ok = display::begin();
    if (!display_ok) {
        ESP_LOGE(kTag, "display init failed, continuing headless");
    }

    touch::begin();
    utils::begin();

    if (!wifi::begin()) {
        ESP_LOGW(kTag, "wifi bringup failed, continuing without WiFi");
    }
    companion::begin();

    if (display_ok) {
        ui::begin();
    }

    ESP_LOGI(kTag, "system ready");
    while (true) {
        touch::poll();
        if (display_ok) {
            ui::tick();
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

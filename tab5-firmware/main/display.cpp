#include "display.h"

#include <M5GFX.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

namespace display {
namespace {

static const char *kTag = "display";

// Raw esp-bsp (esp_lcd_ili9881c) has no ST7123 TDDI panel driver at all --
// only GT911-vs-ST7123 touch got fixed via the BSP patch (see
// components/m5stack_tab5). This unit's actual display panel never got
// driven correctly by that path (ili9881c ID read: 0x0,0x0,0x0 -- wrong
// chip, same signature as the GT911 miss). M5GFX ships a real
// Panel_ST7123 with Tab5 auto-detection that probes the same I2C address
// (0x55) our own probe found, so it's used here as the actual display +
// touch driver, with LVGL layered on top via a manual flush/tick bridge
// (bypassing esp_lvgl_port, which only knows how to drive a raw
// esp_lcd_panel_handle_t, not M5GFX's own panel abstraction).
M5GFX gfx;

lv_display_t *s_display = nullptr;
lv_indev_t *s_indev = nullptr;
SemaphoreHandle_t s_mutex = nullptr;
uint8_t s_rotation = 1;  // M5GFX rotation index; 1 = landscape, matches OrcSDR's proven config

void lvgl_flush_cb(lv_display_t *disp, const lv_area_t *area, uint8_t *px_map) {
    const int32_t w = area->x2 - area->x1 + 1;
    const int32_t h = area->y2 - area->y1 + 1;
    gfx.pushImage(area->x1, area->y1, w, h, reinterpret_cast<const uint16_t *>(px_map));
    lv_display_flush_ready(disp);
}

void lvgl_touch_read_cb(lv_indev_t *, lv_indev_data_t *data) {
    int32_t x = 0;
    int32_t y = 0;
    if (gfx.getTouch(&x, &y) > 0) {
        data->point.x = x;
        data->point.y = y;
        data->state = LV_INDEV_STATE_PRESSED;
    } else {
        data->state = LV_INDEV_STATE_RELEASED;
    }
}

void lvgl_pump_task(void *) {
    uint32_t last_ms = static_cast<uint32_t>(esp_timer_get_time() / 1000ULL);
    while (true) {
        const uint32_t now_ms = static_cast<uint32_t>(esp_timer_get_time() / 1000ULL);
        lv_tick_inc(now_ms - last_ms);
        last_ms = now_ms;
        if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
            lv_timer_handler();
            xSemaphoreGive(s_mutex);
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

}  // namespace

bool begin() {
    if (!gfx.init()) {
        ESP_LOGE(kTag, "M5GFX init failed (no display panel detected)");
        return false;
    }
    gfx.setRotation(s_rotation);
    gfx.setBrightness(180);
    ESP_LOGI(kTag, "display ready via M5GFX (%dx%d)", gfx.width(), gfx.height());

    s_mutex = xSemaphoreCreateMutex();
    lv_init();

    s_display = lv_display_create(gfx.width(), gfx.height());
    lv_display_set_color_format(s_display, LV_COLOR_FORMAT_RGB565);

    constexpr size_t kBufLines = 60;
    const size_t buf_size = static_cast<size_t>(gfx.width()) * kBufLines * 2;
    void *buf1 = heap_caps_malloc(buf_size, MALLOC_CAP_SPIRAM);
    if (buf1 == nullptr) {
        ESP_LOGE(kTag, "LVGL draw buffer alloc failed");
        return false;
    }
    lv_display_set_buffers(s_display, buf1, nullptr, buf_size, LV_DISPLAY_RENDER_MODE_PARTIAL);
    lv_display_set_flush_cb(s_display, lvgl_flush_cb);

    s_indev = lv_indev_create();
    lv_indev_set_type(s_indev, LV_INDEV_TYPE_POINTER);
    lv_indev_set_read_cb(s_indev, lvgl_touch_read_cb);
    lv_indev_set_display(s_indev, s_display);

    xTaskCreate(lvgl_pump_task, "lvgl_pump", 6144, nullptr, tskIDLE_PRIORITY + 2, nullptr);
    return true;
}

bool lock(uint32_t timeout_ms) {
    return xSemaphoreTake(s_mutex, pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
}

void unlock() {
    xSemaphoreGive(s_mutex);
}

void cycle_rotation() {
    s_rotation = (s_rotation + 1) % 4;
    gfx.setRotation(s_rotation);
    lv_display_set_resolution(s_display, gfx.width(), gfx.height());
}

void set_rotation(lv_disp_rotation_t) {
    // Unused externally; M5GFX rotation is driven through cycle_rotation().
}

lv_disp_rotation_t rotation() {
    return static_cast<lv_disp_rotation_t>(s_rotation);
}

uint16_t width() {
    return static_cast<uint16_t>(gfx.width());
}

uint16_t height() {
    return static_cast<uint16_t>(gfx.height());
}

lv_display_t *handle() {
    return s_display;
}

lv_indev_t *input_device() {
    return s_indev;
}

}  // namespace display

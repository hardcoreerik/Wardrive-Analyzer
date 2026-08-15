#include "ui.h"

#include <stdio.h>

#include <algorithm>
#include <string>
#include <vector>

#include "lvgl.h"

#include "companion.h"
#include "display.h"
#include "oui.h"
#include "touch.h"
#include "utils.h"
#include "wifi.h"

namespace ui {
namespace {

enum class ScreenId {
    Home,
    TouchTest,
    DisplayTest,
    SystemInfo,
    WifiScan,
    CompanionLink,
    SerialBridge,
};

#if LVGL_VERSION_MAJOR >= 9
static inline lv_obj_t *active_screen() { return lv_screen_active(); }
#else
static inline lv_obj_t *active_screen() { return lv_scr_act(); }
#endif

const lv_color_t kBg = lv_color_hex(0x090312);
const lv_color_t kPanel = lv_color_hex(0x12051E);
const lv_color_t kPanel2 = lv_color_hex(0x1B0A2A);
const lv_color_t kCyan = lv_color_hex(0x00F5D4);
const lv_color_t kTeal = lv_color_hex(0x00C8FF);
const lv_color_t kText = lv_color_hex(0xE6FFFA);
const lv_color_t kMuted = lv_color_hex(0x80C7C0);
const lv_color_t kWarn = lv_color_hex(0xFFC857);
const lv_color_t kDanger = lv_color_hex(0xFF6B6B);

ScreenId s_screen = ScreenId::Home;
uint8_t s_pattern = 0;
uint32_t s_last_status_ms = 0;

lv_obj_t *s_root = nullptr;
lv_obj_t *s_status_bar = nullptr;
lv_obj_t *s_status_label = nullptr;
lv_obj_t *s_content = nullptr;

lv_obj_t *s_touch_label = nullptr;
lv_obj_t *s_touch_plane = nullptr;
lv_obj_t *s_touch_dot = nullptr;
lv_obj_t *s_pattern_host = nullptr;

lv_obj_t *s_wifi_status_label = nullptr;
lv_obj_t *s_wifi_list = nullptr;
wifi::ScanState s_wifi_last_rendered = wifi::ScanState::Idle;

lv_obj_t *s_companion_status_label = nullptr;
lv_obj_t *s_companion_list = nullptr;
companion::LinkState s_companion_last_rendered = companion::LinkState::Idle;

int32_t clamp_i32(int32_t v, int32_t lo, int32_t hi) {
    return std::min(hi, std::max(lo, v));
}

void style_screen(lv_obj_t *obj) {
    lv_obj_set_style_bg_color(obj, kBg, 0);
    lv_obj_set_style_text_color(obj, kText, 0);
    lv_obj_set_style_border_width(obj, 0, 0);
}

void style_panel(lv_obj_t *obj) {
    lv_obj_set_style_bg_color(obj, kPanel, 0);
    lv_obj_set_style_bg_opa(obj, LV_OPA_COVER, 0);
    lv_obj_set_style_border_color(obj, lv_color_hex(0x00A3C4), 0);
    lv_obj_set_style_border_opa(obj, LV_OPA_70, 0);
    lv_obj_set_style_border_width(obj, 1, 0);
    lv_obj_set_style_radius(obj, 6, 0);
    lv_obj_set_style_pad_all(obj, 12, 0);
    lv_obj_set_style_text_color(obj, kText, 0);
}

void style_button(lv_obj_t *btn, lv_color_t accent) {
    lv_obj_set_style_bg_color(btn, kPanel2, 0);
    lv_obj_set_style_bg_color(btn, lv_color_darken(kPanel2, 40), LV_STATE_PRESSED);
    lv_obj_set_style_border_color(btn, accent, 0);
    lv_obj_set_style_border_width(btn, 2, 0);
    lv_obj_set_style_radius(btn, 6, 0);
    lv_obj_set_style_text_color(btn, kText, 0);
}

lv_obj_t *label(lv_obj_t *parent, const char *text, lv_color_t color = kText) {
    lv_obj_t *l = lv_label_create(parent);
    lv_label_set_text(l, text);
    lv_obj_set_style_text_color(l, color, 0);
    lv_label_set_long_mode(l, LV_LABEL_LONG_WRAP);
    return l;
}

// Screen titles ("WIFI SCAN" etc) -- Tab5's panel is 5" at 1280x720
// (~294 PPI), high density for its size. Default body text is Montserrat
// 24; titles use 32 to actually read as headers at this pixel density.
lv_obj_t *header(lv_obj_t *parent, const char *text, lv_color_t color) {
    lv_obj_t *l = label(parent, text, color);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_32, 0);
    return l;
}

void refresh_status_bar() {
    if (!s_status_label) {
        return;
    }

    const utils::SystemStatus status = utils::read_status();
    std::string line = "WARDRIVE TAB5  |  ";
    line += status.wifi + "  |  ";
    line += status.sd_card + "  |  ";
    line += status.battery + "  |  ";
    line += status.heap + "  |  ";
    line += status.psram;
    lv_label_set_text(s_status_label, line.c_str());
}

void clear_content() {
    s_touch_label = nullptr;
    s_touch_plane = nullptr;
    s_touch_dot = nullptr;
    s_pattern_host = nullptr;
    s_wifi_status_label = nullptr;
    s_wifi_list = nullptr;
    s_wifi_last_rendered = wifi::ScanState::Idle;
    s_companion_status_label = nullptr;
    s_companion_list = nullptr;
    s_companion_last_rendered = companion::LinkState::Idle;
    if (s_content) {
        lv_obj_clean(s_content);
    }
}

void build_base() {
    lv_obj_clean(active_screen());
    s_root = active_screen();
    style_screen(s_root);

    constexpr int32_t kStatusBarHeight = 64;

    s_status_bar = lv_obj_create(s_root);
    lv_obj_set_size(s_status_bar, LV_PCT(100), kStatusBarHeight);
    lv_obj_align(s_status_bar, LV_ALIGN_TOP_MID, 0, 0);
    lv_obj_set_style_bg_color(s_status_bar, lv_color_hex(0x05070D), 0);
    lv_obj_set_style_border_width(s_status_bar, 0, 0);
    lv_obj_set_style_border_side(s_status_bar, LV_BORDER_SIDE_BOTTOM, 0);
    lv_obj_set_style_pad_hor(s_status_bar, 16, 0);
    lv_obj_set_style_pad_ver(s_status_bar, 8, 0);

    s_status_label = label(s_status_bar, "Wardrive Analyzer booting...", kCyan);
    lv_obj_set_width(s_status_label, LV_PCT(100));

    s_content = lv_obj_create(s_root);
    style_screen(s_content);
    lv_obj_set_size(s_content, LV_PCT(100), display::height() - kStatusBarHeight);
    lv_obj_align(s_content, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_pad_all(s_content, 24, 0);
}

void show_home();
void show_touch_test();
void show_display_test();
void show_system_info();
void show_wifi_scan();
void show_companion_link();
void show_serial_bridge();

void back_cb(lv_event_t *) {
    show_home();
}

void rotate_cb(lv_event_t *) {
    display::cycle_rotation();
    build_base();
    show_home();
}

// Sized against OrcSDR's hardware-proven button dimensions (500x120) on
// this same 5" 1280x720 panel -- trimmed down a bit since our home screen
// packs 6 nav buttons into a wrapped grid rather than one prominent
// action button, but kept well clear of the old 260x68 (illegible/hard
// to tap at this pixel density).
lv_obj_t *button(lv_obj_t *parent, const char *text, lv_color_t accent, lv_event_cb_t cb, void *user_data = nullptr) {
    lv_obj_t *btn = lv_btn_create(parent);
    style_button(btn, accent);
    lv_obj_set_size(btn, 400, 110);
    lv_obj_add_event_cb(btn, cb, LV_EVENT_CLICKED, user_data);
    lv_obj_t *t = lv_label_create(btn);
    lv_label_set_text(t, text);
    lv_obj_set_style_text_font(t, &lv_font_montserrat_28, 0);
    lv_obj_center(t);
    return btn;
}

void show_home_cb(lv_event_t *e) {
    const uintptr_t id = reinterpret_cast<uintptr_t>(lv_event_get_user_data(e));
    if (id == 1) {
        show_touch_test();
    } else if (id == 2) {
        show_display_test();
    } else if (id == 3) {
        show_system_info();
    } else if (id == 4) {
        show_companion_link();
    } else if (id == 5) {
        show_serial_bridge();
    } else if (id == 6) {
        show_wifi_scan();
    } else {
        show_home();
    }
}

void draw_pattern() {
    if (!s_pattern_host) {
        return;
    }

    lv_obj_clean(s_pattern_host);
    style_panel(s_pattern_host);

    if ((s_pattern % 2) == 0) {
        static const lv_color_t bars[] = {
            lv_color_hex(0xFF0000), lv_color_hex(0xFF7A00), lv_color_hex(0xFFE600), lv_color_hex(0x00FF62),
            lv_color_hex(0x00E0FF), lv_color_hex(0x0062FF), lv_color_hex(0xAB00FF), lv_color_hex(0xFFFFFF),
        };
        lv_obj_set_flex_flow(s_pattern_host, LV_FLEX_FLOW_ROW);
        lv_obj_set_flex_align(s_pattern_host, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER);
        for (size_t i = 0; i < sizeof(bars) / sizeof(bars[0]); ++i) {
            lv_obj_t *bar = lv_obj_create(s_pattern_host);
            lv_obj_set_style_bg_color(bar, bars[i], 0);
            lv_obj_set_style_border_width(bar, 0, 0);
            lv_obj_set_style_radius(bar, 0, 0);
            lv_obj_set_style_pad_all(bar, 0, 0);
            lv_obj_set_flex_grow(bar, 1);
            lv_obj_set_height(bar, LV_PCT(100));
        }
    } else {
        lv_obj_set_layout(s_pattern_host, LV_LAYOUT_GRID);
        static lv_coord_t cols[] = {LV_GRID_FR(1), LV_GRID_FR(1), LV_GRID_FR(1), LV_GRID_FR(1), LV_GRID_TEMPLATE_LAST};
        static lv_coord_t rows[] = {LV_GRID_FR(1), LV_GRID_FR(1), LV_GRID_FR(1), LV_GRID_TEMPLATE_LAST};
        lv_obj_set_grid_dsc_array(s_pattern_host, cols, rows);
        for (int r = 0; r < 3; ++r) {
            for (int c = 0; c < 4; ++c) {
                lv_obj_t *cell = lv_obj_create(s_pattern_host);
                const bool even = ((r + c) % 2) == 0;
                lv_obj_set_style_bg_color(cell, even ? lv_color_hex(0x072B3B) : lv_color_hex(0x1A0E28), 0);
                lv_obj_set_style_border_color(cell, even ? kTeal : kCyan, 0);
                lv_obj_set_style_border_width(cell, 1, 0);
                lv_obj_set_style_radius(cell, 0, 0);
                lv_obj_set_style_pad_all(cell, 0, 0);
                lv_obj_set_grid_cell(cell, LV_GRID_ALIGN_STRETCH, c, 1, LV_GRID_ALIGN_STRETCH, r, 1);
            }
        }
    }
}

void pattern_cb(lv_event_t *) {
    ++s_pattern;
    draw_pattern();
}

void show_home() {
    s_screen = ScreenId::Home;
    clear_content();

    lv_obj_set_flex_flow(s_content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(s_content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    header(s_content, "WARDRIVE ANALYZER TAB5", kCyan);
    label(s_content, "ESP-IDF hardware foundation for display, touch, diagnostics, and companion integration stubs.", kMuted);

    lv_obj_t *grid = lv_obj_create(s_content);
    style_screen(grid);
    lv_obj_set_size(grid, LV_PCT(98), LV_SIZE_CONTENT);
    lv_obj_set_style_pad_top(grid, 14, 0);
    lv_obj_set_flex_flow(grid, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(grid, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    button(grid, "Touch Test", kCyan, show_home_cb, reinterpret_cast<void *>(1));
    button(grid, "Display Test", kTeal, show_home_cb, reinterpret_cast<void *>(2));
    button(grid, "System Info", kWarn, show_home_cb, reinterpret_cast<void *>(3));
    button(grid, "WiFi Scan", lv_color_hex(0xFF61E6), show_home_cb, reinterpret_cast<void *>(6));
    button(grid, "Companion Link", lv_color_hex(0x78FF85), show_home_cb, reinterpret_cast<void *>(4));
    button(grid, "Serial Bridge", kDanger, show_home_cb, reinterpret_cast<void *>(5));

    lv_obj_t *rotate_btn = button(s_content, "Rotate Screen", kMuted, rotate_cb);
    lv_obj_set_size(rotate_btn, 320, 90);
}

void show_touch_test() {
    s_screen = ScreenId::TouchTest;
    clear_content();

    lv_obj_set_flex_flow(s_content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(s_content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
    button(s_content, "Back", kMuted, back_cb);

    header(s_content, "TOUCH TEST", kCyan);
    label(s_content, "Touch data uses BSP LVGL input. GT911/ST7123 I2C probe is shown as diagnostics.", kMuted);
    s_touch_label = label(s_content, "Touch: waiting", kWarn);
    label(s_content, touch::probe_summary().c_str(), kMuted);

    s_touch_plane = lv_obj_create(s_content);
    style_panel(s_touch_plane);
    lv_obj_set_size(s_touch_plane, 560, 320);

    s_touch_dot = lv_obj_create(s_touch_plane);
    lv_obj_set_size(s_touch_dot, 18, 18);
    lv_obj_set_style_radius(s_touch_dot, LV_RADIUS_CIRCLE, 0);
    lv_obj_set_style_bg_color(s_touch_dot, kCyan, 0);
    lv_obj_set_style_border_width(s_touch_dot, 0, 0);
    lv_obj_add_flag(s_touch_dot, LV_OBJ_FLAG_HIDDEN);
}

void show_display_test() {
    s_screen = ScreenId::DisplayTest;
    clear_content();

    lv_obj_set_flex_flow(s_content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(s_content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
    button(s_content, "Back", kMuted, back_cb);

    header(s_content, "DISPLAY TEST", kTeal);
    label(s_content, "Use Toggle Pattern and Rotate to validate panel orientation, colors, and redraw path.", kMuted);

    lv_obj_t *row = lv_obj_create(s_content);
    style_screen(row);
    lv_obj_set_size(row, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    button(row, "Toggle Pattern", kTeal, pattern_cb);
    button(row, "Rotate", kWarn, rotate_cb);

    s_pattern_host = lv_obj_create(s_content);
    lv_obj_set_size(s_pattern_host, LV_PCT(98), 360);
    draw_pattern();
}

void show_system_info() {
    s_screen = ScreenId::SystemInfo;
    clear_content();

    lv_obj_set_flex_flow(s_content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(s_content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
    button(s_content, "Back", kMuted, back_cb);
    header(s_content, "SYSTEM INFO", kWarn);

    lv_obj_t *panel = lv_obj_create(s_content);
    style_panel(panel);
    lv_obj_set_width(panel, LV_PCT(98));
    lv_obj_t *txt = label(panel, utils::system_info_text().c_str(), kText);
    lv_obj_set_width(txt, LV_PCT(100));
}

void wifi_scan_cb(lv_event_t *) {
    wifi::start_scan();
}

void show_wifi_scan() {
    s_screen = ScreenId::WifiScan;
    clear_content();

    lv_obj_set_flex_flow(s_content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(s_content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);

    lv_obj_t *row = lv_obj_create(s_content);
    style_screen(row);
    lv_obj_set_size(row, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    button(row, "Back", kMuted, back_cb);
    button(row, "Scan", lv_color_hex(0xFF61E6), wifi_scan_cb);

    header(s_content, "WIFI SCAN", lv_color_hex(0xFF61E6));
    s_wifi_status_label = label(s_content, wifi::status_text().c_str(), kMuted);

    s_wifi_list = lv_obj_create(s_content);
    style_panel(s_wifi_list);
    lv_obj_set_size(s_wifi_list, LV_PCT(98), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(s_wifi_list, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(s_wifi_list, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);

    if (wifi::available()) {
        wifi::start_scan();
    }
}

void companion_discover_cb(lv_event_t *) {
    companion::start_discovery();
}

void show_companion_link() {
    s_screen = ScreenId::CompanionLink;
    clear_content();

    lv_obj_set_flex_flow(s_content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(s_content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);

    lv_obj_t *row = lv_obj_create(s_content);
    style_screen(row);
    lv_obj_set_size(row, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    button(row, "Back", kMuted, back_cb);
    button(row, "Discover", lv_color_hex(0x78FF85), companion_discover_cb);

    header(s_content, "COMPANION LINK", lv_color_hex(0x78FF85));
    s_companion_status_label = label(s_content, companion::status_text().c_str(), kMuted);

    const auto &c = utils::companion_contract();
    std::string contract_line = "mDNS " + std::string(c.mdns_type) + "  port " + std::to_string(c.default_port);
    label(s_content, contract_line.c_str(), kMuted);

    s_companion_list = lv_obj_create(s_content);
    style_panel(s_companion_list);
    lv_obj_set_size(s_companion_list, LV_PCT(98), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(s_companion_list, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(s_companion_list, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
    label(s_companion_list, "Tap Discover to find the Wardrive Desktop app on this network.", kMuted);

    companion::start_discovery();
}

void show_serial_bridge() {
    s_screen = ScreenId::SerialBridge;
    clear_content();

    lv_obj_set_flex_flow(s_content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(s_content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
    button(s_content, "Back", kMuted, back_cb);
    header(s_content, "SERIAL BRIDGE", kDanger);

    const auto &s = utils::serial_bridge_contract();
    std::string body;
    body.reserve(512);
    body += "USB-host serial is intentionally a v2 integration.\n\n";
    body += "Target: " + std::string(s.label) + "\n";
    body += "Baud: " + std::to_string(s.baud) + "\n";
    body += "Line ending: " + std::string(s.line_ending) + "\n\n";
    body += "Reserved controls: connect, disconnect, send command, terminal mirror, export log.";

    lv_obj_t *panel = lv_obj_create(s_content);
    style_panel(panel);
    lv_obj_set_width(panel, LV_PCT(98));
    lv_obj_t *txt = label(panel, body.c_str(), kText);
    lv_obj_set_width(txt, LV_PCT(100));
}

void update_touch_test() {
    if (s_screen != ScreenId::TouchTest || !s_touch_label || !s_touch_plane || !s_touch_dot) {
        return;
    }

    const touch::TouchState t = touch::state();
    char line[128];
    snprintf(
        line,
        sizeof(line),
        "Touch: %s x=%d y=%d edge=%lums",
        t.pressed ? "pressed" : "released",
        static_cast<int>(t.x),
        static_cast<int>(t.y),
        static_cast<unsigned long>(t.last_change_ms)
    );
    lv_label_set_text(s_touch_label, line);

    if (!t.pressed) {
        lv_obj_add_flag(s_touch_dot, LV_OBJ_FLAG_HIDDEN);
        return;
    }

    const int32_t plane_w = lv_obj_get_width(s_touch_plane);
    const int32_t plane_h = lv_obj_get_height(s_touch_plane);
    const int32_t dot_w = lv_obj_get_width(s_touch_dot);
    const int32_t dot_h = lv_obj_get_height(s_touch_dot);
    const int32_t x = (static_cast<int32_t>(t.x) * plane_w) / static_cast<int32_t>(display::width());
    const int32_t y = (static_cast<int32_t>(t.y) * plane_h) / static_cast<int32_t>(display::height());

    const int32_t x_max = (plane_w - dot_w) > 0 ? static_cast<int32_t>(plane_w - dot_w) : 0;
    const int32_t y_max = (plane_h - dot_h) > 0 ? static_cast<int32_t>(plane_h - dot_h) : 0;

    lv_obj_set_pos(
        s_touch_dot,
        clamp_i32(x - dot_w / 2, 0, x_max),
        clamp_i32(y - dot_h / 2, 0, y_max)
    );
    lv_obj_clear_flag(s_touch_dot, LV_OBJ_FLAG_HIDDEN);
}

void update_wifi_scan() {
    if (s_screen != ScreenId::WifiScan || !s_wifi_status_label || !s_wifi_list) {
        return;
    }

    const wifi::ScanState state = wifi::scan_state();
    lv_label_set_text(s_wifi_status_label, wifi::status_text().c_str());

    if (state == s_wifi_last_rendered) {
        return;
    }
    s_wifi_last_rendered = state;

    if (state != wifi::ScanState::Done) {
        return;
    }

    lv_obj_clean(s_wifi_list);
    const std::vector<wifi::AccessPoint> aps = wifi::results();
    if (aps.empty()) {
        label(s_wifi_list, "No networks found", kMuted);
        return;
    }
    for (const auto &ap : aps) {
        const std::string vendor = oui::lookup_vendor(ap.bssid);
        const std::string vendor_tag = vendor.empty() ? "" : ("[" + vendor + "]");
        char line[128];
        snprintf(
            line, sizeof(line), "%-24s ch%-2u %4ddBm %s%s",
            ap.ssid.empty() ? "(hidden)" : ap.ssid.c_str(),
            static_cast<unsigned>(ap.channel),
            static_cast<int>(ap.rssi),
            ap.secure ? "" : "OPEN ",
            vendor_tag.c_str()
        );
        label(s_wifi_list, line, ap.secure ? kText : kWarn);
    }
}

void update_companion_link() {
    if (s_screen != ScreenId::CompanionLink || !s_companion_status_label || !s_companion_list) {
        return;
    }

    const companion::LinkState state = companion::state();
    lv_label_set_text(s_companion_status_label, companion::status_text().c_str());

    if (state == s_companion_last_rendered) {
        return;
    }
    s_companion_last_rendered = state;

    if (state != companion::LinkState::Connected) {
        return;
    }

    lv_obj_clean(s_companion_list);
    const std::vector<companion::SessionSummary> sessions = companion::sessions();
    if (sessions.empty()) {
        label(s_companion_list, "Connected, but no sessions yet.", kMuted);
        return;
    }
    for (const auto &s : sessions) {
        char line[128];
        snprintf(
            line, sizeof(line), "%-20s %-20s %u networks",
            s.name.empty() ? s.id.c_str() : s.name.c_str(),
            s.started_at.c_str(),
            static_cast<unsigned>(s.network_count)
        );
        label(s_companion_list, line, kText);
    }
}

}  // namespace

void begin() {
    if (!display::lock(0)) {
        return;
    }
    build_base();
    show_home();
    refresh_status_bar();
    display::unlock();
}

void tick() {
    if (!display::lock(0)) {
        return;
    }

    const uint32_t now = lv_tick_get();
    if (now - s_last_status_ms >= 1000) {
        refresh_status_bar();
        s_last_status_ms = now;
    }

    update_touch_test();
    update_wifi_scan();
    update_companion_link();
    display::unlock();
}

}  // namespace ui

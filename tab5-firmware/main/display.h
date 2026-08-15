#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "lvgl.h"

namespace display {

bool begin();
bool lock(uint32_t timeout_ms = 0);
void unlock();

void cycle_rotation();
void set_rotation(lv_disp_rotation_t rotation);
lv_disp_rotation_t rotation();

uint16_t width();
uint16_t height();
lv_display_t *handle();
lv_indev_t *input_device();

}  // namespace display

#include <android/log.h>
#include <iostream>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#define LOG_TAG "StealthAgent"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

__attribute__((constructor)) void on_load() {
  LOGI("Agent loaded successfully via stealth injection!");
}

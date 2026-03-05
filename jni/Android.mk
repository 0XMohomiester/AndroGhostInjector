LOCAL_PATH := $(call my-dir)/..

# Build Agent Shared Library
include $(CLEAR_VARS)
LOCAL_MODULE := stealth_agent
LOCAL_SRC_FILES := agent/main.cpp
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

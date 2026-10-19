#include <cstdint>
#include <cstddef>
#include "SceTypes.hpp"
#include "prx/libc/include/General.hpp"
#include <cstring>
#include <map>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
std::mutex g_infoMutex;
std::map<int32_t, std::vector<unsigned char>> g_info;

constexpr std::size_t ParamBytes = 16;
constexpr std::size_t MaxPathBytes = 1023;
constexpr std::size_t MaxRingSeconds = 3600;
constexpr int FormatMp4AvcAac = 0;
constexpr int FormatWebmVp9Opus = 1;
constexpr int StatusNone = 0;
constexpr int StatusRunning = 1;
constexpr int StatusPaused = 2;

struct Param {
    std::size_t size;
    std::int32_t ringSeconds;
    std::int32_t format;
};

std::mutex g_sessionMutex;
int g_status = StatusNone;

[[noreturn]] void Fail(const char* function, const std::string& why) {
    throw std::logic_error(std::string(function) + ": " + why);
}

Param ReadParam(const void* param, const char* function) {
    const auto* bytes = static_cast<const unsigned char*>(param);
    Param read{};
    std::memcpy(&read, bytes, sizeof(read));
    if (read.size < ParamBytes) Fail(function, "parameter size " + std::to_string(read.size) + " is smaller than the structure");
    if (read.format != FormatMp4AvcAac && read.format != FormatWebmVp9Opus)
        Fail(function, "container format " + std::to_string(read.format) + " is not supported");
    if (read.ringSeconds < 0 || static_cast<std::size_t>(read.ringSeconds) > MaxRingSeconds)
        Fail(function, "ring buffer of " + std::to_string(read.ringSeconds) + " seconds is out of range");
    return read;
}

void RequireSession(const char* function) {
    if (g_status == StatusNone) Fail(function, "no recording session is open");
}
}

extern "C" {

int APS5_VABI sceVideoRecordingClose(int discard) {
    (void)discard;
    std::lock_guard lock(g_sessionMutex);
    RequireSession(__func__);
    g_status = StatusNone;
    return 0;
}

int APS5_VABI sceVideoRecordingGetInfo(int32_t info, void* data, size_t size) {
    if (data == nullptr) APS5_INVALID_ARG_EX;
    std::lock_guard lock(g_infoMutex);
    const auto found = g_info.find(info);
    if (found == g_info.end()) throw std::logic_error(std::string(__func__) + ": info " + std::to_string(info) + " was never set");
    if (size < found->second.size()) APS5_INVALID_ARG_EX;
    std::memcpy(data, found->second.data(), found->second.size());
    return 0;
}

int APS5_VABI sceVideoRecordingGetStatus(void) {
    std::lock_guard lock(g_sessionMutex);
    return g_status;
}

int APS5_VABI sceVideoRecordingOpen(const char* path, const void* param, void* heap, int heapSize) {
    if (path == nullptr) APS5_INVALID_ARG_EX;
    if (param == nullptr || heap == nullptr) APS5_INVALID_ARG_EX;
    if (heapSize <= 0) APS5_INVALID_ARG_EX;
    ReadParam(param, __func__);
    const std::size_t length = std::strlen(path);
    if (length > MaxPathBytes) Fail(__func__, "path is longer than " + std::to_string(MaxPathBytes) + " bytes");
    std::lock_guard lock(g_sessionMutex);
    if (g_status != StatusNone) Fail(__func__, "a recording session is already open");
    g_status = StatusPaused;
    return 0;
}

int APS5_VABI sceVideoRecordingQueryMemSize(const void* param) {
    (void)param;
 NotImplemented_nid_no_patch(__func__);
    return 0;
}

int APS5_VABI sceVideoRecordingSetInfo(int32_t info, const void* data, size_t size) {
    if (data == nullptr && size != 0) APS5_INVALID_ARG_EX;
    const auto* bytes = static_cast<const unsigned char*>(data);
    std::lock_guard lock(g_infoMutex);
    g_info[info].assign(bytes, bytes + size);
    return 0;
}

int APS5_VABI sceVideoRecordingStart(void) {
    std::lock_guard lock(g_sessionMutex);
    RequireSession(__func__);
    g_status = StatusRunning;
    return 0;
}

int APS5_VABI sceVideoRecordingStop(void) {
    std::lock_guard lock(g_sessionMutex);
    RequireSession(__func__);
    if (g_status != StatusRunning) Fail(__func__, "the recorder is not capturing");
    g_status = StatusPaused;
    return 0;
}

APS5_EXPORT("iQS6DUtLybE", videoRecordingUnknown_iQS6DUtLybE);
int APS5_VABI videoRecordingUnknown_iQS6DUtLybE(void) {
 NotImplemented_nid_no_patch("iQS6DUtLybE");
 return 0;
}

}

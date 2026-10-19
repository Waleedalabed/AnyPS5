#include "prx/libc/include/general/VabiMacros.hpp"
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" {
int APS5_VABI sceVideoRecordingGetStatus(void);
int APS5_VABI sceVideoRecordingQueryMemSize(const void* param);
int APS5_VABI sceVideoRecordingOpen(const char* path, const void* param, void* heap, int heapSize);
int APS5_VABI sceVideoRecordingStart(void);
int APS5_VABI sceVideoRecordingStop(void);
int APS5_VABI sceVideoRecordingClose(int discard);
int APS5_VABI sceVideoRecordingGetInfo(std::int32_t info, void* data, std::size_t size);
int APS5_VABI sceVideoRecordingSetInfo(std::int32_t info, const void* data, std::size_t size);
}

namespace {

void Require(bool value) {
    if (!value) std::abort();
}

template <typename Function>
void RequireThrows(Function function) {
    try {
        function();
    } catch (const std::logic_error&) {
        return;
    } catch (const std::runtime_error&) {
        return;
    }
    std::abort();
}

struct Param {
    std::size_t size;
    std::int32_t ringSeconds;
    std::int32_t format;
};

Param MakeParam(std::size_t size, std::int32_t ringSeconds, std::int32_t format) {
    return Param{size, ringSeconds, format};
}

}

int main() {
    Require(sceVideoRecordingGetStatus() == 0);
    RequireThrows([] { sceVideoRecordingStart(); });
    RequireThrows([] { sceVideoRecordingStop(); });
    RequireThrows([] { sceVideoRecordingClose(0); });

    const Param param = MakeParam(sizeof(Param), 900, 0);
    RequireThrows([&] { sceVideoRecordingQueryMemSize(&param); });

    std::vector<std::uint8_t> heap(4096);
    Require(sceVideoRecordingOpen("video.mp4", &param, heap.data(), 4096) == 0);
    Require(sceVideoRecordingGetStatus() == 2);
    RequireThrows([&] { sceVideoRecordingOpen("second.mp4", &param, heap.data(), 4096); });
    RequireThrows([] { sceVideoRecordingStop(); });

    Require(sceVideoRecordingStart() == 0);
    Require(sceVideoRecordingGetStatus() == 1);
    Require(sceVideoRecordingStop() == 0);
    Require(sceVideoRecordingGetStatus() == 2);
    Require(sceVideoRecordingStart() == 0);
    Require(sceVideoRecordingGetStatus() == 1);
    Require(sceVideoRecordingClose(1) == 0);
    Require(sceVideoRecordingGetStatus() == 0);
    RequireThrows([] { sceVideoRecordingClose(0); });

    RequireThrows([&] { sceVideoRecordingOpen(nullptr, &param, heap.data(), 4096); });
    RequireThrows([&] { sceVideoRecordingOpen("video.mp4", nullptr, heap.data(), 4096); });
    RequireThrows([&] { sceVideoRecordingOpen("video.mp4", &param, nullptr, 4096); });
    RequireThrows([&] { sceVideoRecordingOpen("video.mp4", &param, heap.data(), 0); });
    RequireThrows([&] { sceVideoRecordingOpen("video.mp4", &param, heap.data(), -1); });
    RequireThrows([&] {
        const Param bad = MakeParam(sizeof(Param), 900, 2);
        sceVideoRecordingOpen("video.mp4", &bad, heap.data(), 4096);
    });
    RequireThrows([&] {
        const Param bad = MakeParam(sizeof(Param), -1, 0);
        sceVideoRecordingOpen("video.mp4", &bad, heap.data(), 4096);
    });
    RequireThrows([&] {
        const Param bad = MakeParam(sizeof(Param), 3601, 0);
        sceVideoRecordingOpen("video.mp4", &bad, heap.data(), 4096);
    });
    RequireThrows([&] {
        const Param bad = MakeParam(8, 900, 0);
        sceVideoRecordingOpen("video.mp4", &bad, heap.data(), 4096);
    });
    RequireThrows([&] {
        std::string longPath(1024, 'a');
        sceVideoRecordingOpen(longPath.c_str(), &param, heap.data(), 4096);
    });
    Require(sceVideoRecordingGetStatus() == 0);

    const Param webm = MakeParam(sizeof(Param), 3600, 1);
    std::string path(1023, 'b');
    Require(sceVideoRecordingOpen(path.c_str(), &webm, heap.data(), 1) == 0);
    Require(sceVideoRecordingClose(0) == 0);

    const std::uint8_t blob[] = {1, 2, 3, 4};
    Require(sceVideoRecordingSetInfo(7, blob, sizeof(blob)) == 0);
    std::uint8_t read[4]{};
    Require(sceVideoRecordingGetInfo(7, read, sizeof(read)) == 0 && std::memcmp(read, blob, sizeof(blob)) == 0);
    RequireThrows([] { std::uint8_t small[3]{}; sceVideoRecordingGetInfo(7, small, sizeof(small)); });
    RequireThrows([] { std::uint8_t out[4]{}; sceVideoRecordingGetInfo(8, out, sizeof(out)); });
    RequireThrows([] { sceVideoRecordingGetInfo(7, nullptr, 4); });
}

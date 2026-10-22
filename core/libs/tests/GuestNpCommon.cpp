#include "prx/libc/include/general/VabiMacros.hpp"
#include "SceTypes.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

namespace {

struct OnlineId {
    char data[16];
    std::int8_t term;
    std::int8_t dummy[3];
};

struct NpIdentity {
    OnlineId handle;
    std::uint8_t opt[8];
    std::uint8_t reserved[8];
};

struct CalloutEntry {
    CalloutEntry* next;
    void* handler;
    std::int64_t deadline;
    std::uint64_t arg;
};

struct CalloutContext {
    Pthread thread;
    PthreadMutex mutex;
    PthreadCond cond;
    std::int32_t active;
    std::int32_t stopRequested;
    CalloutEntry* head;
};

constexpr int InvalidArgument = static_cast<int>(0x80550003u);
constexpr int NotMatch = static_cast<int>(0x80550609u);
constexpr int CalloutNotInitialized = static_cast<int>(0x80558001u);
constexpr int CalloutAlreadyInitialized = static_cast<int>(0x80558002u);
constexpr int CalloutDuplicateEntry = static_cast<int>(0x80558006u);
constexpr int CondTimedOut = static_cast<int>(0x8055800Bu);
constexpr int MutexBusy = static_cast<int>(0x8055800Fu);

}

extern "C" {
int APS5_VABI sceNpCmpOnlineId(const OnlineId* first, const OnlineId* second);
int APS5_VABI sceNpCmpNpId(const NpIdentity* first, const NpIdentity* second);
int APS5_VABI sceNpCmpNpIdInOrder(const NpIdentity* first, const NpIdentity* second, std::int32_t* order);
int APS5_VABI sceNpIntIsValidOnlineId(const OnlineId* id);
int APS5_VABI sceNpMutexInit(PthreadMutex* mutex, const char* name, std::uint64_t flags);
int APS5_VABI sceNpMutexDestroy(PthreadMutex* mutex);
int APS5_VABI sceNpMutexLock(PthreadMutex* mutex);
int APS5_VABI sceNpMutexUnlock(PthreadMutex* mutex);
int APS5_VABI sceNpMutexTryLock(PthreadMutex* mutex);
int APS5_VABI sceNpCondInit(PthreadCond* cond, const char* name, std::uint64_t flags);
int APS5_VABI sceNpCondDestroy(PthreadCond* cond);
int APS5_VABI sceNpCondTimedwait(PthreadCond* cond, PthreadMutex* mutex, std::uint32_t usec);
int APS5_VABI sceNpGetSystemClockUsec(std::int64_t* usec);
int APS5_VABI sceNpCalloutInitCtx(CalloutContext* context, const char* name, std::uint64_t stackSize, std::int32_t priority, std::uint64_t affinityMask);
int APS5_VABI sceNpCalloutStartOnCtx(CalloutContext* context, CalloutEntry* entry, std::uint64_t delayUsec, std::uint64_t handler, std::uint64_t arg);
int APS5_VABI sceNpCalloutStopOnCtx(CalloutContext* context, CalloutEntry* entry, std::uint32_t* removed);
void APS5_VABI sceNpCalloutTermCtx(CalloutContext* context);
}

namespace {

std::atomic<std::uint64_t> g_fired{0};

void APS5_VABI RecordCallout(std::uint64_t arg) {
    g_fired.fetch_add(arg);
}

void Require(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "NpCommon: %s\n", message);
        std::abort();
    }
}

OnlineId MakeOnlineId(const char* text) {
    OnlineId id{};
    std::memcpy(id.data, text, std::strlen(text));
    return id;
}

void CheckIdentifiers() {
    const OnlineId alice = MakeOnlineId("alice_01");
    const OnlineId bob = MakeOnlineId("bob-02");
    Require(sceNpCmpOnlineId(&alice, &alice) == 0, "equal online ids");
    Require(sceNpCmpOnlineId(&alice, &bob) == NotMatch, "different online ids");
    Require(sceNpCmpOnlineId(nullptr, &bob) == InvalidArgument, "null online id");

    NpIdentity first{alice, {}, {}};
    NpIdentity second = first;
    Require(sceNpCmpNpId(&first, &second) == 0, "equal np ids");
    second.opt[3] = 1;
    Require(sceNpCmpNpId(&first, &second) == NotMatch, "np ids differing in opt");
    std::int32_t order = 7;
    Require(sceNpCmpNpIdInOrder(&first, &second, &order) == 0 && order == -1, "opt orders np ids");
    Require(sceNpCmpNpIdInOrder(&second, &first, &order) == 0 && order == 1, "reversed order");
    Require(sceNpCmpNpIdInOrder(&first, &first, &order) == 0 && order == 0, "same np id order");
    Require(sceNpCmpNpIdInOrder(&first, &second, nullptr) == InvalidArgument, "null order");

    Require(sceNpIntIsValidOnlineId(&alice) == 1, "valid online id");
    const OnlineId shortId = MakeOnlineId("ab");
    const OnlineId leading = MakeOnlineId("_abc");
    const OnlineId spaced = MakeOnlineId("ab cd");
    Require(sceNpIntIsValidOnlineId(&shortId) == 0, "online id shorter than 3");
    Require(sceNpIntIsValidOnlineId(&leading) == 0, "online id starting with a symbol");
    Require(sceNpIntIsValidOnlineId(&spaced) == 0, "online id with a space");
    OnlineId unterminated = alice;
    unterminated.term = 'x';
    Require(sceNpIntIsValidOnlineId(&unterminated) == 0, "unterminated online id");
    Require(sceNpIntIsValidOnlineId(nullptr) == 0, "null online id is not valid");
}

void CheckLocks() {
    PthreadMutex mutex = nullptr;
    Require(sceNpMutexInit(&mutex, "np-test", 0) == 0, "mutex init");
    Require(sceNpMutexLock(&mutex) == 0, "mutex lock");
    int busy = 0;
    std::thread other([&] { busy = sceNpMutexTryLock(&mutex); });
    other.join();
    Require(busy == MutexBusy, "trylock on a held mutex reports busy");
    Require(sceNpMutexUnlock(&mutex) == 0, "mutex unlock");
    Require(sceNpMutexDestroy(&mutex) == 0, "mutex destroy");

    PthreadMutex recursive = nullptr;
    Require(sceNpMutexInit(&recursive, "np-recursive", 1) == 0, "recursive mutex init");
    Require(sceNpMutexLock(&recursive) == 0 && sceNpMutexLock(&recursive) == 0, "recursive relock");
    Require(sceNpMutexUnlock(&recursive) == 0 && sceNpMutexUnlock(&recursive) == 0, "recursive unlock");
    Require(sceNpMutexDestroy(&recursive) == 0, "recursive destroy");

    PthreadMutex waitMutex = nullptr;
    PthreadCond cond = nullptr;
    Require(sceNpMutexInit(&waitMutex, "np-wait", 0) == 0, "wait mutex init");
    Require(sceNpCondInit(&cond, "np-cond", 0) == 0, "cond init");
    Require(sceNpMutexLock(&waitMutex) == 0, "wait mutex lock");
    Require(sceNpCondTimedwait(&cond, &waitMutex, 1000) == CondTimedOut, "timed wait times out");
    Require(sceNpMutexUnlock(&waitMutex) == 0, "wait mutex unlock");
    Require(sceNpCondDestroy(&cond) == 0, "cond destroy");
    Require(sceNpMutexDestroy(&waitMutex) == 0, "wait mutex destroy");

    std::int64_t before = 0;
    std::int64_t after = 0;
    Require(sceNpGetSystemClockUsec(&before) == 0, "system clock");
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    Require(sceNpGetSystemClockUsec(&after) == 0 && after - before >= 2000, "system clock advances in microseconds");
}

void CheckCallouts() {
    CalloutContext context{};
    CalloutEntry entry{};
    Require(sceNpCalloutStartOnCtx(&context, &entry, 0, 0, 0) == CalloutNotInitialized, "start before init");
    Require(sceNpCalloutInitCtx(&context, "np-callout", 0x10000, 0, 0) == 0, "callout init");
    Require(sceNpCalloutInitCtx(&context, "np-callout", 0x10000, 0, 0) == CalloutAlreadyInitialized, "second callout init");

    const auto handler = reinterpret_cast<std::uint64_t>(&RecordCallout);
    CalloutEntry late{};
    Require(sceNpCalloutStartOnCtx(&context, &late, 10000000, handler, 100) == 0, "schedule a late callout");
    Require(sceNpCalloutStartOnCtx(&context, &late, 10000000, handler, 100) == CalloutDuplicateEntry, "duplicate callout");
    std::uint32_t removed = 9;
    Require(sceNpCalloutStopOnCtx(&context, &late, &removed) == 0 && removed == 1, "stop a pending callout");
    Require(sceNpCalloutStopOnCtx(&context, &late, &removed) == 0 && removed == 0, "stop an absent callout");

    Require(sceNpCalloutStartOnCtx(&context, &entry, 1000, handler, 5) == 0, "schedule a callout");
    for (int attempt = 0; attempt < 2000 && g_fired.load() == 0; ++attempt) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    Require(g_fired.load() == 5, "callout fired once with its argument");
    sceNpCalloutTermCtx(&context);
    Require(context.active == 0, "callout context terminated");
}

}

int main() {
    CheckIdentifiers();
    CheckLocks();
    CheckCallouts();
    return 0;
}

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include "SceTypes.hpp"
#include "prx/libc/include/General.hpp"
#include "prx/libkernel/KernelErrors.hpp"

namespace {

constexpr int NP_ERROR_INVALID_ARGUMENT = static_cast<int>(0x80550003u);
constexpr int NP_UTIL_ERROR_NOT_MATCH = static_cast<int>(0x80550609u);
constexpr int NP_CALLOUT_ERROR_NOT_INITIALIZED = static_cast<int>(0x80558001u);
constexpr int NP_CALLOUT_ERROR_ALREADY_INITIALIZED = static_cast<int>(0x80558002u);
constexpr int NP_CALLOUT_ERROR_DUPLICATE_ENTRY = static_cast<int>(0x80558006u);
constexpr int NP_LW_COND_ERROR_TIMEDOUT = static_cast<int>(0x8055800Bu);
constexpr int NP_LW_MUTEX_ERROR_BUSY = static_cast<int>(0x8055800Fu);
constexpr std::size_t ONLINE_ID_MAX_LENGTH = 16;
constexpr int MUTEX_TYPE_RECURSIVE = 2;
constexpr KernelClockid CLOCK_MONOTONIC_ID = 4;

struct NpCommonOnlineId {
    char data[ONLINE_ID_MAX_LENGTH];
    std::int8_t term;
    std::int8_t dummy[3];
};

struct NpCommonId {
    NpCommonOnlineId handle;
    std::uint8_t opt[8];
    std::uint8_t reserved[8];
};

static_assert(sizeof(NpCommonOnlineId) == 20);
static_assert(sizeof(NpCommonId) == 36);

using NpCalloutHandler = void (APS5_VABI*)(std::uint64_t);

struct NpCalloutEntry {
    NpCalloutEntry* next;
    NpCalloutHandler handler;
    std::int64_t deadlineUsec;
    std::uint64_t arg;
};

struct NpCalloutContext {
    Pthread thread;
    PthreadMutex mutex;
    PthreadCond cond;
    std::int32_t active;
    std::int32_t stopRequested;
    NpCalloutEntry* head;
};

static_assert(sizeof(NpCalloutEntry) == 0x20);
static_assert(offsetof(NpCalloutContext, thread) == 0x00);
static_assert(offsetof(NpCalloutContext, mutex) == 0x08);
static_assert(offsetof(NpCalloutContext, cond) == 0x10);
static_assert(offsetof(NpCalloutContext, active) == 0x18);
static_assert(offsetof(NpCalloutContext, stopRequested) == 0x1c);
static_assert(offsetof(NpCalloutContext, head) == 0x20);
static_assert(sizeof(NpCalloutContext) == 0x28);

}

extern "C" {

int APS5_VABI scePthreadMutexattrInit(PthreadMutexattr* attr);
int APS5_VABI scePthreadMutexattrDestroy(PthreadMutexattr* attr);
int APS5_VABI scePthreadMutexattrSettype(PthreadMutexattr* attr, int type);
int APS5_VABI scePthreadMutexInit(PthreadMutex* mutex, const PthreadMutexattr* attr, const char* name);
int APS5_VABI scePthreadMutexDestroy(PthreadMutex* mutex);
int APS5_VABI scePthreadMutexLock(PthreadMutex* mutex);
int APS5_VABI scePthreadMutexUnlock(PthreadMutex* mutex);
int APS5_VABI scePthreadMutexTrylock(PthreadMutex* mutex);
int APS5_VABI scePthreadCondattrInit(PthreadCondattr* attr);
int APS5_VABI scePthreadCondattrDestroy(PthreadCondattr* attr);
int APS5_VABI scePthreadCondInit(PthreadCond* cond, const PthreadCondattr* attr, const char* name);
int APS5_VABI scePthreadCondDestroy(PthreadCond* cond);
int APS5_VABI scePthreadCondSignal(PthreadCond* cond);
int APS5_VABI scePthreadCondWait(PthreadCond* cond, PthreadMutex* mutex);
int APS5_VABI scePthreadCondTimedwait(PthreadCond* cond, PthreadMutex* mutex, KernelUseconds usec);
int APS5_VABI scePthreadAttrInit(PthreadAttr* attr);
int APS5_VABI scePthreadAttrDestroy(PthreadAttr* attr);
int APS5_VABI scePthreadAttrSetstacksize(PthreadAttr* attr, std::size_t stackSize);
int APS5_VABI scePthreadAttrSetaffinity(PthreadAttr* attr, KernelCpumask mask);
int APS5_VABI scePthreadCreate(Pthread* thread, const PthreadAttr* attr, PthreadEntry entry, void* arg, const char* name);
int APS5_VABI scePthreadJoin(Pthread thread, void** result);
int APS5_VABI sceKernelClockGettime(KernelClockid clockId, KernelTimespec* tp);

int APS5_VABI sceNpCondTimedwait(PthreadCond* cond, PthreadMutex* mutex, std::uint32_t usec);
int APS5_VABI sceNpGetSystemClockUsec(std::int64_t* usec);

}

namespace {

void* APS5_VABI CalloutThreadMain(void* argument) {
    auto* context = static_cast<NpCalloutContext*>(argument);
    scePthreadMutexLock(&context->mutex);
    for (;;) {
        std::int64_t nowUsec = 0;
        sceNpGetSystemClockUsec(&nowUsec);
        NpCalloutEntry* entry = context->head;
        std::uint32_t waitUsec = 0;
        if (entry == nullptr) {
            if (context->stopRequested > 0) break;
        } else {
            const auto deadline = static_cast<std::uint64_t>(entry->deadlineUsec);
            const auto now = static_cast<std::uint64_t>(nowUsec);
            if (deadline <= now) {
                context->head = entry->next;
                scePthreadMutexUnlock(&context->mutex);
                if (entry->handler != nullptr) entry->handler(entry->arg);
                scePthreadMutexLock(&context->mutex);
                continue;
            }
            if (context->stopRequested > 0) break;
            const std::uint64_t remaining = deadline - now;
            waitUsec = static_cast<std::uint32_t>(remaining > 0xffffffffu ? 0xffffffffu : remaining);
        }
        sceNpCondTimedwait(&context->cond, &context->mutex, waitUsec);
        if (context->stopRequested > 0) break;
    }
    scePthreadMutexUnlock(&context->mutex);
    return nullptr;
}

int StartCallout(NpCalloutContext* context, NpCalloutEntry* entry, std::int64_t delayUsec, std::uint64_t handler, std::uint64_t arg) {
    if (context->active == 0) return NP_CALLOUT_ERROR_NOT_INITIALIZED;
    entry->next = nullptr;
    entry->handler = reinterpret_cast<NpCalloutHandler>(handler);
    entry->arg = arg;
    sceNpGetSystemClockUsec(&entry->deadlineUsec);
    entry->deadlineUsec += delayUsec;
    scePthreadMutexLock(&context->mutex);
    for (NpCalloutEntry* current = context->head; current != nullptr; current = current->next) {
        if (current == entry) {
            scePthreadMutexUnlock(&context->mutex);
            return NP_CALLOUT_ERROR_DUPLICATE_ENTRY;
        }
    }
    NpCalloutEntry** link = &context->head;
    while (*link != nullptr && (*link)->deadlineUsec < entry->deadlineUsec) link = &(*link)->next;
    entry->next = *link;
    *link = entry;
    scePthreadCondSignal(&context->cond);
    scePthreadMutexUnlock(&context->mutex);
    return 0;
}

}

extern "C" {

int APS5_VABI sceNpCmpOnlineId(const NpCommonOnlineId* first, const NpCommonOnlineId* second) {
    if (first == nullptr || second == nullptr) return NP_ERROR_INVALID_ARGUMENT;
    if (std::strncmp(first->data, second->data, ONLINE_ID_MAX_LENGTH) != 0) return NP_UTIL_ERROR_NOT_MATCH;
    return 0;
}

int APS5_VABI sceNpCmpNpId(const NpCommonId* first, const NpCommonId* second) {
    if (first == nullptr || second == nullptr) return NP_ERROR_INVALID_ARGUMENT;
    if (std::strncmp(first->handle.data, second->handle.data, ONLINE_ID_MAX_LENGTH) != 0) return NP_UTIL_ERROR_NOT_MATCH;
    if (std::memcmp(first->opt, second->opt, sizeof(first->opt)) != 0) return NP_UTIL_ERROR_NOT_MATCH;
    if (std::memcmp(first->reserved, second->reserved, sizeof(first->reserved)) != 0) return NP_UTIL_ERROR_NOT_MATCH;
    return 0;
}

int APS5_VABI sceNpCmpNpIdInOrder(const NpCommonId* first, const NpCommonId* second, std::int32_t* order) {
    if (first == nullptr || second == nullptr || order == nullptr) return NP_ERROR_INVALID_ARGUMENT;
    int compared = std::strncmp(first->handle.data, second->handle.data, ONLINE_ID_MAX_LENGTH);
    if (compared == 0) compared = std::memcmp(first->opt, second->opt, sizeof(first->opt));
    if (compared == 0) compared = std::memcmp(first->reserved, second->reserved, sizeof(first->reserved));
    *order = compared < 0 ? -1 : (compared > 0 ? 1 : 0);
    return 0;
}

int APS5_VABI sceNpIntIsValidOnlineId(const NpCommonOnlineId* id) {
    if (id == nullptr || id->term != 0) return 0;
    const std::size_t length = strnlen(id->data, ONLINE_ID_MAX_LENGTH);
    if (length < 3) return 0;
    if (!std::isalnum(static_cast<unsigned char>(id->data[0]))) return 0;
    for (std::size_t index = 1; index < length; ++index) {
        const auto character = static_cast<unsigned char>(id->data[index]);
        if (!std::isalnum(character) && character != '_' && character != '-') return 0;
    }
    return 1;
}

int APS5_VABI sceNpMutexInit(PthreadMutex* mutex, const char* name, std::uint64_t flags) {
    if ((flags & ~std::uint64_t{1}) != 0) NotImplemented_nid_no_patch("sceNpMutexInit: flags other than the recursive bit");
    PthreadMutexattr attr = nullptr;
    int result = scePthreadMutexattrInit(&attr);
    if (result != 0) return result;
    if ((flags & 1) != 0) result = scePthreadMutexattrSettype(&attr, MUTEX_TYPE_RECURSIVE);
    if (result == 0) result = scePthreadMutexInit(mutex, &attr, name);
    scePthreadMutexattrDestroy(&attr);
    return result;
}

int APS5_VABI sceNpMutexDestroy(PthreadMutex* mutex) {
    return scePthreadMutexDestroy(mutex);
}

int APS5_VABI sceNpMutexLock(PthreadMutex* mutex) {
    return scePthreadMutexLock(mutex);
}

int APS5_VABI sceNpMutexUnlock(PthreadMutex* mutex) {
    return scePthreadMutexUnlock(mutex);
}

int APS5_VABI sceNpMutexTryLock(PthreadMutex* mutex) {
    const int result = scePthreadMutexTrylock(mutex);
    return result == SCE_KERNEL_ERROR_EBUSY ? NP_LW_MUTEX_ERROR_BUSY : result;
}

int APS5_VABI sceNpLwMutexInit(PthreadMutex* mutex, const char* name, std::uint64_t flags) {
    return sceNpMutexInit(mutex, name, flags);
}

int APS5_VABI sceNpLwMutexDestroy(PthreadMutex* mutex) {
    return sceNpMutexDestroy(mutex);
}

int APS5_VABI sceNpLwMutexLock(PthreadMutex* mutex) {
    return sceNpMutexLock(mutex);
}

int APS5_VABI sceNpLwMutexUnlock(PthreadMutex* mutex) {
    return sceNpMutexUnlock(mutex);
}

int APS5_VABI sceNpLwMutexTryLock(PthreadMutex* mutex) {
    return sceNpMutexTryLock(mutex);
}

int APS5_VABI sceNpCondInit(PthreadCond* cond, const char* name, std::uint64_t flags) {
    if (flags != 0) NotImplemented_nid_no_patch("sceNpCondInit: nonzero flags");
    PthreadCondattr attr = nullptr;
    int result = scePthreadCondattrInit(&attr);
    if (result != 0) return result;
    result = scePthreadCondInit(cond, &attr, name);
    scePthreadCondattrDestroy(&attr);
    return result;
}

int APS5_VABI sceNpCondDestroy(PthreadCond* cond) {
    return scePthreadCondDestroy(cond);
}

int APS5_VABI sceNpCondSignal(PthreadCond* cond) {
    return scePthreadCondSignal(cond);
}

int APS5_VABI sceNpCondTimedwait(PthreadCond* cond, PthreadMutex* mutex, std::uint32_t usec) {
    if (usec == 0) return scePthreadCondWait(cond, mutex);
    const int result = scePthreadCondTimedwait(cond, mutex, usec);
    return result == SCE_KERNEL_ERROR_ETIMEDOUT ? NP_LW_COND_ERROR_TIMEDOUT : result;
}

int APS5_VABI sceNpCreateThread(Pthread* thread, PthreadEntry entry, void* arg, std::int32_t priority, std::uint64_t stackSize, std::uint64_t affinityMask, const char* name) {
    if (priority != 0) NotImplemented_nid_no_patch("sceNpCreateThread: a nonzero priority");
    PthreadAttr attr = nullptr;
    int result = scePthreadAttrInit(&attr);
    if (result != 0) return result;
    result = scePthreadAttrSetstacksize(&attr, static_cast<std::size_t>(stackSize));
    if (result == 0 && affinityMask != 0) result = scePthreadAttrSetaffinity(&attr, affinityMask);
    if (result == 0) result = scePthreadCreate(thread, &attr, entry, arg, name);
    scePthreadAttrDestroy(&attr);
    return result;
}

int APS5_VABI sceNpJoinThread(Pthread thread, void** result) {
    return scePthreadJoin(thread, result);
}

int APS5_VABI sceNpGetSystemClockUsec(std::int64_t* usec) {
    KernelTimespec now{};
    const int result = sceKernelClockGettime(CLOCK_MONOTONIC_ID, &now);
    if (result == 0) *usec = static_cast<std::int64_t>(now.tv_sec) * 1000000 + now.tv_nsec / 1000;
    return result;
}

int APS5_VABI sceNpCalloutInitCtx(NpCalloutContext* context, const char* name, std::uint64_t stackSize, std::int32_t priority, std::uint64_t affinityMask) {
    if (context->active >= 1) return NP_CALLOUT_ERROR_ALREADY_INITIALIZED;
    context->stopRequested = 0;
    context->head = nullptr;
    int result = sceNpMutexInit(&context->mutex, name, 1);
    if (result < 0) return result;
    result = sceNpCondInit(&context->cond, name, 0);
    if (result < 0) {
        sceNpMutexDestroy(&context->mutex);
        return result;
    }
    result = sceNpCreateThread(&context->thread, CalloutThreadMain, context, priority, stackSize, affinityMask, name);
    if (result < 0) {
        sceNpCondDestroy(&context->cond);
        sceNpMutexDestroy(&context->mutex);
        return result;
    }
    context->active = 1;
    return 0;
}

int APS5_VABI sceNpCalloutStartOnCtx(NpCalloutContext* context, NpCalloutEntry* entry, std::uint64_t delayUsec, std::uint64_t handler, std::uint64_t arg) {
    return StartCallout(context, entry, static_cast<std::int64_t>(static_cast<std::uint32_t>(delayUsec)), handler, arg);
}

int APS5_VABI sceNpCalloutStartOnCtx64(NpCalloutContext* context, NpCalloutEntry* entry, std::int64_t delayUsec, std::uint64_t handler, std::uint64_t arg) {
    return StartCallout(context, entry, delayUsec, handler, arg);
}

int APS5_VABI sceNpCalloutStopOnCtx(NpCalloutContext* context, NpCalloutEntry* entry, std::uint32_t* removed) {
    if (context->active == 0) return NP_CALLOUT_ERROR_NOT_INITIALIZED;
    scePthreadMutexLock(&context->mutex);
    std::uint32_t found = 0;
    for (NpCalloutEntry** link = &context->head; *link != nullptr; link = &(*link)->next) {
        if (*link == entry) {
            *link = entry->next;
            found = 1;
            break;
        }
    }
    if (removed != nullptr) *removed = found;
    scePthreadMutexUnlock(&context->mutex);
    return 0;
}

void APS5_VABI sceNpCalloutTermCtx(NpCalloutContext* context) {
    if (context->active == 0) return;
    scePthreadMutexLock(&context->mutex);
    context->stopRequested = 1;
    scePthreadCondSignal(&context->cond);
    scePthreadMutexUnlock(&context->mutex);
    sceNpJoinThread(context->thread, nullptr);
    sceNpCondDestroy(&context->cond);
    sceNpMutexDestroy(&context->mutex);
    context->active = 0;
}

}

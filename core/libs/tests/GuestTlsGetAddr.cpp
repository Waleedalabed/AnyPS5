#include "prx/libc/include/general/VabiMacros.hpp"
#include <cstddef>
#include <cstdio>
#include <link.h>
#include <thread>

extern "C" void* APS5_VABI __tls_get_addr_nid_postfix(void* index);
extern "C" void* __tls_get_addr(void* index);

struct TlsIndex {
    unsigned long module;
    unsigned long offset;
};

thread_local int value = 7;

static int FindModule(dl_phdr_info* info, std::size_t, void* data) {
    if (info->dlpi_tls_modid == 0) return 0;
    *static_cast<unsigned long*>(data) = info->dlpi_tls_modid;
    return 1;
}

int main() {
    TlsIndex index{0, 0};
    dl_iterate_phdr(FindModule, &index.module);
    TlsIndex base{index.module, 0};
    index.offset = static_cast<unsigned long>(reinterpret_cast<char*>(&value) - static_cast<char*>(__tls_get_addr(&base)));
    bool main = __tls_get_addr_nid_postfix(&index) == &value;
    value = 9;
    bool other = false;
    std::thread([&] { other = __tls_get_addr_nid_postfix(&index) == &value && value == 7; }).join();
    if (index.module == 0 || !main || !other) {
        std::fprintf(stderr, "__tls_get_addr returned the wrong block\n");
        return 1;
    }
    return 0;
}

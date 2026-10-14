#include "prx/libc/include/general/VabiMacros.hpp"
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

struct FileStream;

extern "C" {
int APS5_VABI sscanf_nid_postfix(const char*, const char*, ...);
int APS5_VABI sscanf_s_nid_postfix(const char*, const char*, ...);
int APS5_VABI vsscanf_nid_postfix(const char*, const char*, void*);
int APS5_VABI vsscanf_s_nid_postfix(const char*, const char*, void*);
int APS5_VABI fscanf_nid_postfix(FileStream*, const char*, ...);
FileStream* APS5_VABI fopen_nid_postfix(const char*, const char*);
int APS5_VABI fclose_nid_postfix(FileStream*);
}

static int failures = 0;

static void Require(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "%s\n", message);
        ++failures;
    }
}

static bool Equals(const std::uint16_t* value, const char* expected) {
    const auto length = std::strlen(expected);
    for (std::size_t index = 0; index < length; ++index) {
        if (value[index] != static_cast<unsigned char>(expected[index])) return false;
    }
    return value[length] == 0;
}

static int APS5_VABI Vsscanf(bool secure, const char* input, const char* format, ...) {
#ifdef _WIN32
    __builtin_sysv_va_list args;
    __builtin_sysv_va_start(args, format);
    const int result = secure ? vsscanf_s_nid_postfix(input, format, args) : vsscanf_nid_postfix(input, format, args);
    __builtin_sysv_va_end(args);
#else
    va_list args;
    va_start(args, format);
    const int result = secure ? vsscanf_s_nid_postfix(input, format, args) : vsscanf_nid_postfix(input, format, args);
    va_end(args);
#endif
    return result;
}

int main() {
    std::uint16_t word[16]{};
    std::uint16_t letters[4]{0xffff, 0xffff, 0xffff, 0xffff};
    std::uint16_t set[16]{};
    int number = 0;
    Require(sscanf_nid_postfix("  hello 42 xyz abcab!", "%ls %d %3lc %l[abc]", word, &number, letters, set) == 4, "sscanf wide count");
    Require(Equals(word, "hello") && number == 42, "sscanf %ls value");
    Require(letters[0] == 'x' && letters[1] == 'y' && letters[2] == 'z' && letters[3] == 0xffff, "sscanf %3lc must store three units and no terminator");
    Require(Equals(set, "abcab"), "sscanf %l[ value");

    std::uint16_t upper[16]{};
    std::uint16_t single[2]{0xffff, 0xffff};
    Require(sscanf_nid_postfix("\xe9t\xe9 q", "%S %C", upper, single) == 2, "sscanf %S %C count");
    Require(upper[0] == 0xe9 && upper[1] == 't' && upper[2] == 0xe9 && upper[3] == 0 && single[0] == 'q' && single[1] == 0xffff,
        "bytes must widen one to one");

    std::uint16_t skipped[4]{};
    Require(sscanf_nid_postfix("one two", "%*ls %ls", skipped) == 1 && Equals(skipped, "two"), "suppressed wide conversion");
    Require(sscanf_nid_postfix("", "%ls", word) == EOF, "empty input must report EOF");
    int count = -1;
    Require(sscanf_nid_postfix("ab12", "%l[a-z]%n", set, &count) == 1 && Equals(set, "ab") && count == 2, "%n after a wide conversion");

    std::uint16_t small[4]{};
    Require(sscanf_s_nid_postfix("abc", "%ls", small, 4u) == 1 && Equals(small, "abc"), "sscanf_s wide fits");
    small[0] = 0xffff;
    Require(sscanf_s_nid_postfix("abcd", "%ls", small, 4u) == 0 && small[0] == 0, "sscanf_s wide overflow must clear the target");
    Require(Vsscanf(false, "wide 7", "%ls %d", word, &number) == 2 && Equals(word, "wide") && number == 7, "vsscanf wide");
    Require(Vsscanf(true, "xy", "%2lc", letters, 2u) == 1 && letters[0] == 'x' && letters[1] == 'y', "vsscanf_s wide");

    const std::filesystem::path path = "guest_scan_wide.txt";
    {
        std::ofstream file(path, std::ios::binary);
        file << "stream 9 tail";
    }
    auto* stream = fopen_nid_postfix("guest_scan_wide.txt", "rb");
    Require(stream != nullptr, "fopen");
    if (stream) {
        std::uint16_t first[16]{};
        char rest[16]{};
        Require(fscanf_nid_postfix(stream, "%ls %d %s", first, &number, rest) == 3, "fscanf wide count");
        Require(Equals(first, "stream") && number == 9 && std::strcmp(rest, "tail") == 0, "fscanf wide values");
        Require(fscanf_nid_postfix(stream, "%ls", first) == EOF, "fscanf at the end");
        fclose_nid_postfix(stream);
    }
    std::filesystem::remove(path);
    return failures == 0 ? 0 : 1;
}

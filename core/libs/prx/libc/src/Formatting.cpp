#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <algorithm>
#include <cstdarg>
#include <cctype>
#include <cstring>
#include <string>
#include <cerrno>
#include <cstdlib>
#include <memory>

#include "prx/libc/include/General.hpp"
#include "SceTypes.hpp"
#include "prx/libc/include/FileStream.hpp"
#include "prx/libc/include/ApplicationHeap.hpp"

#include "prx/libc/include/WindowsFormatting.hpp"

#ifdef _WIN32
#include "prx/libc/include/WindowsScanning.hpp"
#endif

#if defined(__GLIBC__)
extern "C" {
int __isoc99_vsscanf(const char*, const char*, std::va_list) noexcept;
int __isoc99_vfscanf(std::FILE*, const char*, std::va_list);
}
#endif

namespace {

#ifndef _WIN32
bool RequiresGuestFormatting(const char* format) {
    if (format == nullptr) return false;
    while ((format = std::strchr(format, '%')) != nullptr) {
        ++format;
        if (*format == '%') { ++format; continue; }
        while (*format && std::strchr("-+ #0'0123456789.*$", *format)) ++format;
        if (*format == 'S' || *format == 'C' || *format == 'm' || *format == 'p' ||
            (*format == 'l' && (format[1] == 's' || format[1] == 'c' || format[1] == 'p'))) return true;
        if (*format) ++format;
    }
    return false;
}

bool HasGuestWideScan(const char* format) {
    if (format == nullptr) return false;
    while ((format = std::strchr(format, '%')) != nullptr) {
        ++format;
        if (*format == '%') { ++format; continue; }
        while (*format && std::strchr("-+ #0'0123456789.*$", *format)) ++format;
        if (*format == 'S' || *format == 'C' || (*format == 'l' && format[1] != '\0' && std::strchr("sc[", format[1]))) return true;
        if (*format == '[') {
            ++format;
            if (*format == '^') ++format;
            if (*format == ']') ++format;
            while (*format && *format != ']') ++format;
        }
        if (*format) ++format;
    }
    return false;
}
#endif

std::string HostLength(const std::string& length, char conversion) {
#ifdef _WIN32
    if (length == "l" && std::strchr("diouxXn", conversion) != nullptr) return "ll";
#else
    (void)conversion;
#endif
    return length;
}

int HostVsscanf(const char* input, const char* format, std::va_list args) {
#if defined(__GLIBC__)
    return __isoc99_vsscanf(input, format, args);
#else
    return std::vsscanf(input, format, args);
#endif
}

int HostSscanf(const char* input, const char* format, ...) {
    std::va_list args;
    va_start(args, format);
    const int result = HostVsscanf(input, format, args);
    va_end(args);
    return result;
}

#ifndef _WIN32
int HostVfscanf(std::FILE* stream, const char* format, std::va_list args) {
#if defined(__GLIBC__)
    return __isoc99_vfscanf(stream, format, args);
#else
    return std::vfscanf(stream, format, args);
#endif
}

int HostFscanf(std::FILE* stream, const char* format, ...) {
    std::va_list args;
    va_start(args, format);
    const int result = HostVfscanf(stream, format, args);
    va_end(args);
    return result;
}
#endif

class StringSource {
public:
    explicit StringSource(const char* buffer) : buffer(buffer), input(buffer) {}
    int Peek() const { return *input == '\0' ? EOF : static_cast<unsigned char>(*input); }
    void Advance() { ++input; }
    std::int64_t Position() const { return input - buffer; }
    template <typename... TArguments>
    int Scan(const char* directive, TArguments... arguments) { return HostSscanf(input, directive, arguments...); }
    void Consume(int count) { input += count; }

private:
    const char* buffer;
    const char* input;
};

#ifndef _WIN32
class StreamSource {
public:
    explicit StreamSource(std::FILE* stream) : stream(stream) {}
    int Peek() const {
        const int value = std::getc(stream);
        if (value != EOF) std::ungetc(value, stream);
        return value;
    }
    void Advance() {
        if (std::getc(stream) != EOF) ++position;
    }
    std::int64_t Position() const { return position; }
    template <typename... TArguments>
    int Scan(const char* directive, TArguments... arguments) { return HostFscanf(stream, directive, arguments...); }
    void Consume(int count) { position += count; }

private:
    std::FILE* stream;
    std::int64_t position = 0;
};

#endif

bool InSet(int value, const std::string& specifier) {
    if (value == EOF) return false;
    const char text[2] = {static_cast<char>(value), '\0'};
    char probe[2];
    const std::string test = "%1" + specifier;
    return std::sscanf(text, test.c_str(), probe) == 1;
}

template <typename TSource, typename NextPointer, typename NextCapacity>
int ScanGuest(TSource& source, const char* format, bool secure, NextPointer nextPointer, NextCapacity nextCapacity) {
    if (format == nullptr) return EOF;
    int assigned = 0;
    bool converted = false;
    const char* cursor = format;
    const auto skipSpace = [&] {
        while (source.Peek() != EOF && std::isspace(source.Peek())) source.Advance();
    };
    while (*cursor != '\0') {
        if (std::isspace(static_cast<unsigned char>(*cursor))) {
            while (std::isspace(static_cast<unsigned char>(*cursor))) ++cursor;
            skipSpace();
            continue;
        }
        if (*cursor != '%' || cursor[1] == '%') {
            const char expected = *cursor == '%' ? '%' : *cursor;
            cursor += *cursor == '%' ? 2 : 1;
            if (expected == '%') skipSpace();
            const int next = source.Peek();
            if (next != static_cast<unsigned char>(expected)) return !converted && next == EOF ? EOF : assigned;
            source.Advance();
            continue;
        }
        ++cursor;
        const bool suppress = *cursor == '*';
        if (suppress) ++cursor;
        std::string flags;
        while (*cursor == '\'') flags += *cursor++;
        unsigned long width = 0;
        while (std::isdigit(static_cast<unsigned char>(*cursor))) width = width * 10 + static_cast<unsigned long>(*cursor++ - '0');
        if (*cursor == '$') throw std::invalid_argument("Positional scan arguments are not supported by the guest scanner");
        const char* lengthStart = cursor;
        while (std::strchr("hljztL", *cursor) != nullptr && *cursor != '\0') ++cursor;
        std::string length(lengthStart, cursor);
        char conversion = *cursor;
        if (conversion == '\0') return assigned;
        bool wide = false;
        if (conversion == 'S' || conversion == 'C') {
            wide = true;
            conversion = conversion == 'S' ? 's' : 'c';
        } else if (length == "l" && std::strchr("sc[", conversion) != nullptr) {
            wide = true;
        }
        if (wide) length.clear();
        std::string specifier(1, conversion);
        if (conversion == '[') {
            const char* setStart = cursor++;
            if (*cursor == '^') ++cursor;
            if (*cursor == ']') ++cursor;
            while (*cursor != '\0' && *cursor != ']') ++cursor;
            if (*cursor != ']') return assigned;
            specifier.assign(setStart, cursor + 1);
        }
        ++cursor;
        if (conversion == 'n') {
            if (!suppress) {
                void* target = nextPointer();
                if (target == nullptr) return EOF;
                const auto count = source.Position();
                if (length == "hh") *static_cast<signed char*>(target) = static_cast<signed char>(count);
                else if (length == "h") *static_cast<short*>(target) = static_cast<short>(count);
                else if (length.empty()) *static_cast<int*>(target) = static_cast<int>(count);
                else if (length == "l" || length == "ll" || length == "j" || length == "z" || length == "t") {
                    const std::int64_t value = count;
                    std::memcpy(target, &value, sizeof(value));
                } else throw std::invalid_argument("Invalid scan count length");
            }
            continue;
        }
        if (conversion != 'c' && conversion != '[') {
            skipSpace();
            if (source.Peek() == EOF) return converted ? assigned : EOF;
        }
        const bool sized = secure && (conversion == 's' || conversion == 'c' || conversion == '[');
        bool capped = false;
        std::string directive = "%";
        void* target = nullptr;
        if (suppress) directive += '*';
        else {
            target = nextPointer();
            if (target == nullptr) return EOF;
        }
        if (!wide) directive += flags;
        if (sized && !suppress) {
            const auto capacity = static_cast<unsigned long>(nextCapacity());
            const unsigned long limit = conversion == 'c' ? capacity : (capacity == 0 ? 0 : capacity - 1);
            const unsigned long wanted = conversion == 'c' ? (width == 0 ? 1 : width) : width;
            if (limit == 0 || (conversion == 'c' && wanted > limit)) {
                if (capacity != 0) {
                    if (wide) static_cast<std::uint16_t*>(target)[0] = 0;
                    else static_cast<char*>(target)[0] = '\0';
                }
                return assigned;
            }
            capped = wanted == 0 || wanted > limit;
            width = wanted == 0 ? limit : std::min(wanted, limit);
        }
        if (width != 0) directive += std::to_string(width);
#ifndef _WIN32
        const bool widen = wide && !suppress;
        if (widen) directive += 'm';
#else
        const bool widen = false;
        if (wide) directive += 'l';
#endif
        directive += HostLength(length, conversion);
        directive += specifier;
        directive += "%n";
        int consumed = -1;
        int matched = 0;
        char* narrow = nullptr;
        if (suppress) matched = source.Scan(directive.c_str(), &consumed);
        else if (widen) matched = source.Scan(directive.c_str(), &narrow, &consumed);
        else matched = source.Scan(directive.c_str(), target, &consumed);
        const std::unique_ptr<char, decltype(&std::free)> owner(narrow, std::free);
        if (consumed < 0 || (!suppress && matched != 1)) return !converted && source.Peek() == EOF ? EOF : assigned;
        source.Consume(consumed);
        if (widen) {
            const auto count = conversion == 'c' ? static_cast<std::size_t>(width == 0 ? 1 : width) : std::strlen(narrow);
            auto* output = static_cast<std::uint16_t*>(target);
            for (std::size_t index = 0; index < count; ++index) output[index] = static_cast<unsigned char>(narrow[index]);
            if (conversion != 'c') output[count] = 0;
        }
        if (capped && conversion != 'c') {
            const int next = source.Peek();
            bool overflow = false;
            if (conversion == 's') overflow = next != EOF && !std::isspace(next);
            else overflow = InSet(next, specifier);
            if (overflow) {
                if (wide) static_cast<std::uint16_t*>(target)[0] = 0;
                else static_cast<char*>(target)[0] = '\0';
                return assigned;
            }
        }
        converted = true;
        if (!suppress) ++assigned;
    }
    return assigned;
}

template <typename NextPointer, typename NextCapacity>
int ScanGuestString(const char* buffer, const char* format, bool secure, NextPointer nextPointer, NextCapacity nextCapacity) {
    if (buffer == nullptr || format == nullptr) return EOF;
    StringSource source(buffer);
    return ScanGuest(source, format, secure, nextPointer, nextCapacity);
}
}

extern "C" {

int APS5_VABI vasprintf_nid_postfix(char** destination, const char* format, VaList* args) {
    if (!destination) { errno = 22; return -1; }
    *destination = nullptr;
    if (!format || !args) { errno = 22; return -1; }
    try {
#ifdef _WIN32
        std::string text;
        const int count = LibcDetail::FormatWindows(nullptr, 0, format, args, &text);
        const char* source = text.c_str();
#else
        std::string guestText;
        const bool guestFormatting = RequiresGuestFormatting(format);
        char* text = nullptr;
        std::va_list copy;
        va_copy(copy, *reinterpret_cast<std::va_list*>(args));
        const int count = guestFormatting ? LibcDetail::FormatWindows(nullptr, 0, format, args, &guestText) : ::vasprintf(&text, format, copy);
        va_end(copy);
        std::unique_ptr<char, decltype(&std::free)> owner(text, std::free);
        if (count < 0) return -1;
        const char* source = guestFormatting ? guestText.c_str() : text;
#endif
        auto* output = static_cast<char*>(ApplicationHeapAllocate_nid_no_patch(static_cast<size_t>(count) + 1));
        if (!output) {
            errno = 12;
            return -1;
        }
        std::memcpy(output, source, static_cast<size_t>(count) + 1);
        *destination = output;
        return count;
    } catch (const std::bad_alloc&) {
        errno = 12;
        return -1;
    }
}

int APS5_VABI vfprintf_nid_postfix(FileStream* stream, const char* format, VaList* args) {
    if (stream && !stream->IsOpen()) { errno = 9; return -1; }
    auto* native = GetNativeStream(stream);
#ifdef _WIN32
    std::string buffer;
    const int count = LibcDetail::FormatWindows(nullptr, 0, format, args, &buffer);
    const int result = std::fwrite(buffer.data(), 1, static_cast<size_t>(count), native) ==
        static_cast<size_t>(count) ? count : -1;
#else
    if (RequiresGuestFormatting(format)) {
        std::string buffer;
        const int count = LibcDetail::FormatWindows(nullptr, 0, format, args, &buffer);
        const int result = std::fwrite(buffer.data(), 1, static_cast<size_t>(count), native) == static_cast<size_t>(count) ? count : -1;
        stream->SyncStatus();
        return result;
    }
    std::va_list copy;
    va_copy(copy, *reinterpret_cast<std::va_list*>(args));
    const int result = std::vfprintf(native, format, copy);
    va_end(copy);
#endif
    stream->SyncStatus();
    return result;
}

int APS5_VABI fprintf_nid_postfix(FileStream* stream, const char* format, ...) {
#ifdef _WIN32
    __builtin_sysv_va_list args;
    __builtin_sysv_va_start(args, format);
#else
    std::va_list args;
    va_start(args, format);
#endif
    const int result = vfprintf_nid_postfix(stream, format, reinterpret_cast<VaList*>(args));
#ifdef _WIN32
    __builtin_sysv_va_end(args);
#else
    va_end(args);
#endif
    return result;
}

int APS5_VABI fscanf_nid_postfix(FileStream* stream, const char* format, ...) {
    if (stream && !stream->IsOpen()) { errno = 9; return -1; }
    auto* native = GetNativeStream(stream);
#ifdef _WIN32
    __builtin_sysv_va_list args;
    __builtin_sysv_va_start(args, format);
    const int result = LibcDetail::ScanFileWindows_nid_no_patch(native, format, args);
    __builtin_sysv_va_end(args);
#else
    std::va_list args;
    va_start(args, format);
    int result;
    if (HasGuestWideScan(format)) {
        StreamSource source(native);
        result = native ? ScanGuest(source, format, false, [&] { return va_arg(args, void*); }, [] { return 0u; }) : EOF;
    } else {
        result = HostVfscanf(native, format, args);
    }
    va_end(args);
#endif
    stream->SyncStatus();
    return result;
}

#ifdef _WIN32

int APS5_VABI printf_nid_postfix(const char* format, ...) {
    if (!_Stdout_nid_postfix.IsOpen()) { errno = 9; return -1; }
    __builtin_sysv_va_list args;
    __builtin_sysv_va_start(args, format);
    const int result = LibcDetail::PrintWindows(format, args);
    __builtin_sysv_va_end(args);
    return result;
}

int APS5_VABI libc_printf_nid_postfix(const char* format, ...) {
    if (!_Stdout_nid_postfix.IsOpen()) { errno = 9; return -1; }
    __builtin_sysv_va_list args;
    __builtin_sysv_va_start(args, format);
    const int result = LibcDetail::PrintWindows(format, args);
    __builtin_sysv_va_end(args);
    return result;
}

int APS5_VABI snprintf_nid_postfix(char* buffer, size_t size, const char* format, ...) {
    __builtin_sysv_va_list args;
    __builtin_sysv_va_start(args, format);
    const int result = LibcDetail::FormatWindows(buffer, size, format, args);
    __builtin_sysv_va_end(args);
    return result;
}

int APS5_VABI sprintf_nid_postfix(char* buffer, const char* format, ...) {
    __builtin_sysv_va_list args;
    __builtin_sysv_va_start(args, format);
    const int result = LibcDetail::FormatWindows(buffer, SIZE_MAX, format, args);
    __builtin_sysv_va_end(args);
    return result;
}

#else

int APS5_VABI printf_nid_postfix(const char* format, ...) {
    if (!_Stdout_nid_postfix.IsOpen()) { errno = 9; return -1; }
    std::va_list args;
    va_start(args, format);
    const int result = RequiresGuestFormatting(format) ? LibcDetail::PrintWindows(format, args) : std::vprintf(format, args);
    va_end(args);
    return result;
}

int APS5_VABI libc_printf_nid_postfix(const char* format, ...) {
    if (!_Stdout_nid_postfix.IsOpen()) { errno = 9; return -1; }
    std::va_list args;
    va_start(args, format);
    const int result = RequiresGuestFormatting(format) ? LibcDetail::PrintWindows(format, args) : std::vprintf(format, args);
    va_end(args);
    return result;
}

int APS5_VABI snprintf_nid_postfix(char* buffer, size_t size, const char* format, ...) {
    std::va_list args;
    va_start(args, format);
    const int result = RequiresGuestFormatting(format) ? LibcDetail::FormatWindows(buffer, size, format, args) : std::vsnprintf(buffer, size, format, args);
    va_end(args);
    return result;
}

int APS5_VABI sprintf_nid_postfix(char* buffer, const char* format, ...) {
    std::va_list args;
    va_start(args, format);
    const int result = RequiresGuestFormatting(format) ? LibcDetail::FormatWindows(buffer, SIZE_MAX, format, args) : std::vsprintf(buffer, format, args);
    va_end(args);
    return result;
}

#endif

int APS5_VABI vsscanf_nid_postfix(const char* input, const char* format, VaList* args) {
#ifdef _WIN32
    return LibcDetail::ScanWindows(input, format, args);
#else
    if (HasGuestWideScan(format)) {
        LibcDetail::FormatArguments arguments(args);
        return ScanGuestString(input, format, false, [&] { return arguments.Next<void*>(); }, [] { return 0u; });
    }
    std::va_list copy;
    va_copy(copy, *reinterpret_cast<std::va_list*>(args));
    const int result = HostVsscanf(input, format, copy);
    va_end(copy);
    return result;
#endif
}

#ifdef _WIN32
int APS5_VABI sscanf_nid_postfix(const char* input, const char* format, ...) {
    __builtin_sysv_va_list args;
    __builtin_sysv_va_start(args, format);
    const int result = vsscanf_nid_postfix(input, format, reinterpret_cast<VaList*>(args));
    __builtin_sysv_va_end(args);
    return result;
}
#else
int APS5_VABI sscanf_nid_postfix(const char* input, const char* format, ...) {
    std::va_list args;
    va_start(args, format);
    const int result = HasGuestWideScan(format) ? ScanGuestString(input, format, false, [&] { return va_arg(args, void*); }, [] { return 0u; })
                                                : HostVsscanf(input, format, args);
    va_end(args);
    return result;
}
#endif

#ifdef _WIN32

int APS5_VABI sscanf_s_nid_postfix(const char* buffer, const char* format, ...) {
    __builtin_sysv_va_list args;
    __builtin_sysv_va_start(args, format);
    const int result = ScanGuestString(buffer, format, true, [&] { return __builtin_va_arg(args, void*); }, [&] { return __builtin_va_arg(args, unsigned int); });
    __builtin_sysv_va_end(args);
    return result;
}

#else

int APS5_VABI sscanf_s_nid_postfix(const char* buffer, const char* format, ...) {
    std::va_list args;
    va_start(args, format);
    const int result = ScanGuestString(buffer, format, true, [&] { return va_arg(args, void*); }, [&] { return va_arg(args, unsigned int); });
    va_end(args);
    return result;
}

#endif

int APS5_VABI vprintf_nid_postfix(const char* str, VaList* c) {
    if (!_Stdout_nid_postfix.IsOpen()) { errno = 9; return -1; }
#ifdef _WIN32
    return LibcDetail::PrintWindows(str, c);
#else
    if (RequiresGuestFormatting(str)) return LibcDetail::PrintWindows(str, c);
    std::va_list copy;
    va_copy(copy, *reinterpret_cast<std::va_list*>(c));
    const int result = std::vprintf(str, copy);
    va_end(copy);
    return result;
#endif
}

int APS5_VABI vsprintf_nid_postfix(char* str, const char* format, VaList* args) {
#ifdef _WIN32
    return LibcDetail::FormatWindows(str, SIZE_MAX, format, args);
#else
    if (RequiresGuestFormatting(format)) return LibcDetail::FormatWindows(str, SIZE_MAX, format, args);
    std::va_list copy;
    va_copy(copy, *reinterpret_cast<std::va_list*>(args));
    const int result = std::vsprintf(str, format, copy);
    va_end(copy);
    return result;
#endif
}

int APS5_VABI vsnprintf_nid_postfix(char* str, size_t size, const char* format, VaList* c) {
#ifdef _WIN32
    return LibcDetail::FormatWindows(str, size, format, c);
#else
    if (RequiresGuestFormatting(format)) return LibcDetail::FormatWindows(str, size, format, c);
    std::va_list copy;
    va_copy(copy, *reinterpret_cast<std::va_list*>(c));
    const int result = std::vsnprintf(str, size, format, copy);
    va_end(copy);
    return result;
#endif
}

static int FormatSecure(char* buffer, size_t size, const char* format, const void* args) {
    constexpr size_t RsizeMax = SIZE_MAX >> 1;
    int result = -1;
    if (buffer != nullptr && format != nullptr && args != nullptr && size != 0 && size <= RsizeMax) {
        try {
            result = LibcDetail::FormatWindows(buffer, size, format, args, nullptr, true);
        } catch (const LibcDetail::FormatConstraintViolation&) {
        }
    }
    if (result < 0 && buffer != nullptr && size != 0 && size <= RsizeMax) buffer[0] = 0;
    return result;
}

int APS5_VABI vsnprintf_s_nid_postfix(char* buffer, size_t size, const char* format, VaList* args) {
    return FormatSecure(buffer, size, format, args);
}

#ifdef _WIN32

int APS5_VABI vsscanf_s_nid_postfix(const char* buffer, const char* format, VaList* args) {
    LibcDetail::FormatArguments arguments(args);
    return ScanGuestString(buffer, format, true, [&] { return arguments.Next<void*>(); }, [&] { return arguments.Next<unsigned int>(); });
}

int APS5_VABI snprintf_s_nid_postfix(char* buffer, size_t size, const char* format, ...) {
    __builtin_sysv_va_list args;
    __builtin_sysv_va_start(args, format);
    const int result = FormatSecure(buffer, size, format, args);
    __builtin_sysv_va_end(args);
    return result;
}

int APS5_VABI printf_s_nid_postfix(const char* format, ...) {
    __builtin_sysv_va_list args;
    __builtin_sysv_va_start(args, format);
    const int result = LibcDetail::PrintWindows(format, args);
    __builtin_sysv_va_end(args);
    return result;
}

#else

int APS5_VABI vsscanf_s_nid_postfix(const char* buffer, const char* format, VaList* args) {
    LibcDetail::FormatArguments arguments(args);
    return ScanGuestString(buffer, format, true, [&] { return arguments.Next<void*>(); }, [&] { return arguments.Next<unsigned int>(); });
}

int APS5_VABI vsprintf_s_nid_postfix(char* buffer, size_t size, const char* format, VaList* args) {
    if (RequiresGuestFormatting(format)) return LibcDetail::FormatWindows(buffer, size, format, args);
    std::va_list copy;
    va_copy(copy, *reinterpret_cast<std::va_list*>(args));
    const int result = std::vsnprintf(buffer, size, format, copy);
    va_end(copy);
    return result;
}

int APS5_VABI sprintf_s_nid_postfix(char* buffer, size_t size, const char* format, ...) {
    std::va_list args;
    va_start(args, format);
    const int result = RequiresGuestFormatting(format) ? LibcDetail::FormatWindows(buffer, size, format, args) : std::vsnprintf(buffer, size, format, args);
    va_end(args);
    return result;
}

int APS5_VABI snprintf_s_nid_postfix(char* buffer, size_t size, const char* format, ...) {
    std::va_list args;
    va_start(args, format);
    const int result = FormatSecure(buffer, size, format, args);
    va_end(args);
    return result;
}

int APS5_VABI printf_s_nid_postfix(const char* format, ...) {
    std::va_list args;
    va_start(args, format);
    const int result = RequiresGuestFormatting(format) ? LibcDetail::PrintWindows(format, args) : std::vprintf(format, args);
    va_end(args);
    return result;
}

#endif

int APS5_VABI puts_nid_postfix(const char* s) {
    if (!_Stdout_nid_postfix.IsOpen()) { errno = 9; return -1; }
    return std::puts(s);
}

}

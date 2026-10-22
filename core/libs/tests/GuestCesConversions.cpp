#include "prx/libc/include/general/VabiMacros.hpp"
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
void* APS5_VABI sceCesUcsProfileInitEucKr(void*);
void* APS5_VABI sceCesUcsProfileInitUhc(void*);
void* APS5_VABI sceCesUcsProfileInitBig5Cp950(void*);
void* APS5_VABI sceCesUcsProfileInitEucJpCp51932(void*);
void* APS5_VABI sceCesUcsProfileInitSJis1997Cp932(void*);
const std::uint8_t* APS5_VABI sceCesRefersUcsProfileCp1252(void);
int APS5_VABI sceCesMbcsUcsContextInit(void*, const void*);
int APS5_VABI sceCesBig5ToUcs2(const void*, const std::uint8_t*, std::uint32_t, std::uint32_t*, std::uint16_t*);
int APS5_VABI sceCesBig5ToUtf16le(const void*, const std::uint8_t*, std::uint32_t, std::uint32_t*, std::uint16_t*, std::uint32_t, std::uint32_t*);
int APS5_VABI sceCesBig5ToUtf32be(const void*, const std::uint8_t*, std::uint32_t, std::uint32_t*, std::uint32_t*);
int APS5_VABI sceCesUtf16beToBig5(const std::uint16_t*, std::uint32_t, std::uint32_t*, const void*, std::uint8_t*, std::uint32_t, std::uint32_t*);
int APS5_VABI sceCesUtf32ToBig5(std::uint32_t, const void*, std::uint8_t*, std::uint32_t, std::uint32_t*);
int APS5_VABI sceCesSJisToUtf8(const void*, const std::uint8_t*, std::uint32_t, std::uint32_t*, std::uint8_t*, std::uint32_t, std::uint32_t*);
int APS5_VABI sceCesUtf8ToSJis(const std::uint8_t*, std::uint32_t, std::uint32_t*, const void*, std::uint8_t*, std::uint32_t, std::uint32_t*);
int APS5_VABI sceCesUtf16ToSJis(const std::uint16_t*, std::uint32_t, std::uint32_t*, const void*, std::uint8_t*, std::uint32_t, std::uint32_t*);
int APS5_VABI sceCesEucJpToUtf32(const void*, const std::uint8_t*, std::uint32_t, std::uint32_t*, std::uint32_t*);
int APS5_VABI sceCesUcs2ToEucJp(std::uint16_t, const void*, std::uint8_t*, std::uint32_t, std::uint32_t*);
int APS5_VABI sceCesEucKrToUtf16(const void*, const std::uint8_t*, std::uint32_t, std::uint32_t*, std::uint16_t*, std::uint32_t, std::uint32_t*);
int APS5_VABI sceCesUtf32ToEucKr(std::uint32_t, const void*, std::uint8_t*, std::uint32_t, std::uint32_t*);
int APS5_VABI sceCesUtf32leToUhc(const std::uint32_t*, const void*, std::uint8_t*, std::uint32_t, std::uint32_t*);
int APS5_VABI sceCesUhcToUcs2(const void*, const std::uint8_t*, std::uint32_t, std::uint32_t*, std::uint16_t*);
int APS5_VABI sceCesSbcToUtf16be(const std::uint8_t*, std::uint8_t, std::uint16_t*, std::uint32_t, std::uint32_t*);
int APS5_VABI sceCesSbcToUtf32(const std::uint8_t*, std::uint8_t, std::uint32_t*);
int APS5_VABI sceCesUtf32leToSbc(const std::uint32_t*, const std::uint8_t*, std::uint8_t*);
int APS5_VABI sceCesUtf16ToSbc(const std::uint16_t*, std::uint32_t, std::uint32_t*, const std::uint8_t*, std::uint8_t*);
int APS5_VABI sceCesUcs2ToSbc(std::uint16_t, const std::uint8_t*, std::uint8_t*);
int APS5_VABI sceCesMbcsStrToUtf16Str(void*, const std::uint8_t*, std::uint32_t, std::uint32_t*, std::uint16_t*, std::uint32_t, std::uint32_t*);
int APS5_VABI sceCesMbcsStrGetUtf32Len(void*, const std::uint8_t*, std::uint32_t, std::uint32_t*, std::uint32_t*);
int APS5_VABI sceCesUtf32StrToMbcsStr(void*, const std::uint32_t*, std::uint32_t, std::uint32_t*, std::uint8_t*, std::uint32_t, std::uint32_t*);
int APS5_VABI sceCesUtf16StrGetMbcsLen(void*, const std::uint16_t*, std::uint32_t, std::uint32_t*, std::uint32_t*);
}

namespace {

constexpr int invalidParameter = static_cast<int>(0x805C0001);
constexpr int invalidSrcBuffer = static_cast<int>(0x805C0010);
constexpr int srcBufferEnd = static_cast<int>(0x805C0011);
constexpr int invalidEncode = static_cast<int>(0x805C0014);
constexpr int unassignedCode = static_cast<int>(0x805C0020);
constexpr int invalidDstBuffer = static_cast<int>(0x805C0030);
constexpr int dstBufferEnd = static_cast<int>(0x805C0031);

void Require(bool value) {
    if (!value) std::abort();
}

const std::uint8_t* Bytes(const char* text) {
    return reinterpret_cast<const std::uint8_t*>(text);
}

std::uint8_t ByteAt(const void* data, std::size_t index) {
    return static_cast<const std::uint8_t*>(data)[index];
}

alignas(16) std::uint8_t g_big5Sheet[4096];
alignas(16) std::uint8_t g_sjisSheet[4096];
alignas(16) std::uint8_t g_eucJpSheet[4096];
alignas(16) std::uint8_t g_eucKrSheet[4096];
alignas(16) std::uint8_t g_uhcSheet[4096];

void CheckBig5(const void* big5) {
    std::uint32_t consumed = 0;
    std::uint16_t ucs2 = 0;
    Require(sceCesBig5ToUcs2(big5, Bytes("\xA4\xA4"), 2, &consumed, &ucs2) == 0 && consumed == 2 && ucs2 == 0x4E2D);
    Require(sceCesBig5ToUcs2(big5, Bytes("\xA4"), 1, &consumed, &ucs2) == srcBufferEnd);
    Require(sceCesBig5ToUcs2(nullptr, Bytes("A"), 1, &consumed, &ucs2) == invalidParameter);
    Require(sceCesBig5ToUcs2(big5, nullptr, 1, &consumed, &ucs2) == invalidSrcBuffer);
    Require(sceCesBig5ToUcs2(big5, Bytes("A"), 1, &consumed, nullptr) == invalidDstBuffer);

    std::uint16_t utf16[2] = {};
    std::uint32_t produced = 0;
    Require(sceCesBig5ToUtf16le(big5, Bytes("\xA4\xA4"), 2, &consumed, utf16, 2, &produced) == 0 && produced == 1);
    Require(ByteAt(utf16, 0) == 0x2D && ByteAt(utf16, 1) == 0x4E);
    Require(sceCesBig5ToUtf16le(big5, Bytes("\xA4\xA4"), 2, &consumed, utf16, 0, &produced) == dstBufferEnd);

    std::uint32_t utf32 = 0;
    Require(sceCesBig5ToUtf32be(big5, Bytes("\xA4\xA4"), 2, &consumed, &utf32) == 0);
    Require(ByteAt(&utf32, 0) == 0 && ByteAt(&utf32, 1) == 0 && ByteAt(&utf32, 2) == 0x4E && ByteAt(&utf32, 3) == 0x2D);

    const std::uint8_t bigEndian[2] = {0x4E, 0x2D};
    std::uint8_t encoded[4] = {};
    Require(sceCesUtf16beToBig5(reinterpret_cast<const std::uint16_t*>(bigEndian), 1, &consumed, big5, encoded, sizeof(encoded), &produced) == 0);
    Require(consumed == 1 && produced == 2 && encoded[0] == 0xA4 && encoded[1] == 0xA4);
    Require(sceCesUtf32ToBig5(0x4E2D, big5, encoded, 1, &produced) == dstBufferEnd);
    Require(sceCesUtf32ToBig5(0xD800, big5, encoded, sizeof(encoded), &produced) == invalidEncode);
    Require(sceCesUtf32ToBig5(0x1F600, big5, encoded, sizeof(encoded), &produced) == unassignedCode);
    Require(sceCesUtf32ToBig5('Z', big5, encoded, sizeof(encoded), &produced) == 0 && produced == 1 && encoded[0] == 'Z');
}

void CheckJapanese(const void* sjis, const void* eucJp) {
    std::uint32_t consumed = 0;
    std::uint32_t produced = 0;
    std::uint8_t utf8[4] = {};
    Require(sceCesSJisToUtf8(sjis, Bytes("\x82\xA0"), 2, &consumed, utf8, sizeof(utf8), &produced) == 0);
    Require(consumed == 2 && produced == 3 && std::memcmp(utf8, "\xE3\x81\x82", 3) == 0);

    std::uint8_t encoded[4] = {};
    Require(sceCesUtf8ToSJis(Bytes("\xE3\x81\x82"), 3, &consumed, sjis, encoded, sizeof(encoded), &produced) == 0);
    Require(consumed == 3 && produced == 2 && encoded[0] == 0x82 && encoded[1] == 0xA0);
    Require(sceCesUtf8ToSJis(Bytes("\xE3\x81"), 2, &consumed, sjis, encoded, sizeof(encoded), &produced) == srcBufferEnd);

    const std::uint16_t lone[1] = {0xDC00};
    Require(sceCesUtf16ToSJis(lone, 1, &consumed, sjis, encoded, sizeof(encoded), &produced) == invalidEncode);
    const std::uint16_t katakana[1] = {0xFF71};
    Require(sceCesUtf16ToSJis(katakana, 1, &consumed, sjis, encoded, sizeof(encoded), &produced) == 0 && produced == 1 && encoded[0] == 0xB1);

    std::uint32_t utf32 = 0;
    Require(sceCesEucJpToUtf32(eucJp, Bytes("\xA4\xA2"), 2, &consumed, &utf32) == 0 && consumed == 2 && utf32 == 0x3042);
    Require(sceCesUcs2ToEucJp(0x3042, eucJp, encoded, sizeof(encoded), &produced) == 0 && produced == 2 && encoded[0] == 0xA4 && encoded[1] == 0xA2);
    Require(sceCesUcs2ToEucJp(0x3042, sjis, encoded, sizeof(encoded), &produced) == invalidParameter);
}

void CheckKorean(const void* eucKr, const void* uhc) {
    std::uint32_t consumed = 0;
    std::uint32_t produced = 0;
    std::uint16_t utf16[1] = {};
    Require(sceCesEucKrToUtf16(eucKr, Bytes("\xB0\xA1"), 2, &consumed, utf16, 1, &produced) == 0 && utf16[0] == 0xAC00 && produced == 1);

    std::uint8_t encoded[4] = {};
    Require(sceCesUtf32ToEucKr(0xAC00, eucKr, encoded, sizeof(encoded), &produced) == 0 && encoded[0] == 0xB0 && encoded[1] == 0xA1);
    Require(sceCesUtf32ToEucKr(0xAC02, eucKr, encoded, sizeof(encoded), &produced) == unassignedCode);

    const std::uint8_t littleEndian[4] = {0x02, 0xAC, 0x00, 0x00};
    Require(sceCesUtf32leToUhc(reinterpret_cast<const std::uint32_t*>(littleEndian), uhc, encoded, sizeof(encoded), &produced) == 0);
    Require(produced == 2 && encoded[0] == 0x81 && encoded[1] == 0x41);
    std::uint16_t ucs2 = 0;
    Require(sceCesUhcToUcs2(uhc, encoded, produced, &consumed, &ucs2) == 0 && ucs2 == 0xAC02);
}

void CheckSingleByte(const std::uint8_t* cp1252) {
    std::uint16_t utf16[1] = {};
    std::uint32_t produced = 0;
    Require(sceCesSbcToUtf16be(cp1252, 0x80, utf16, 1, &produced) == 0 && produced == 1);
    Require(ByteAt(utf16, 0) == 0x20 && ByteAt(utf16, 1) == 0xAC);
    std::uint32_t utf32 = 0;
    Require(sceCesSbcToUtf32(cp1252, 0xE9, &utf32) == 0 && utf32 == 0xE9);
    Require(sceCesSbcToUtf32(nullptr, 0xE9, &utf32) == invalidParameter);

    std::uint8_t sbc = 0;
    const std::uint8_t euro[4] = {0xAC, 0x20, 0x00, 0x00};
    Require(sceCesUtf32leToSbc(reinterpret_cast<const std::uint32_t*>(euro), cp1252, &sbc) == 0 && sbc == 0x80);
    std::uint32_t consumed = 0;
    const std::uint16_t tradeMark[1] = {0x2122};
    Require(sceCesUtf16ToSbc(tradeMark, 1, &consumed, cp1252, &sbc) == 0 && consumed == 1 && sbc == 0x99);
    Require(sceCesUcs2ToSbc(0x0410, cp1252, &sbc) == unassignedCode);
}

void CheckStrings(const void* sjis) {
    alignas(16) std::uint8_t context[64] = {};
    Require(sceCesMbcsUcsContextInit(context, sjis) == 0);
    std::uint32_t consumed = 0;
    std::uint32_t produced = 0;
    std::uint16_t utf16[4] = {};
    Require(sceCesMbcsStrToUtf16Str(context, Bytes("\x82\xA0" "A"), 3, &consumed, utf16, 4, &produced) == 0);
    Require(consumed == 3 && produced == 2 && utf16[0] == 0x3042 && utf16[1] == 'A');
    Require(sceCesMbcsStrToUtf16Str(context, Bytes("\x82\xA0" "A"), 3, &consumed, utf16, 1, &produced) == dstBufferEnd);
    Require(sceCesMbcsStrGetUtf32Len(context, Bytes("\x82\xA0" "AB"), 4, &consumed, &produced) == 0 && produced == 3);

    const std::uint32_t utf32[3] = {0x3042, 'B', 0};
    std::uint8_t encoded[8] = {};
    Require(sceCesUtf32StrToMbcsStr(context, utf32, 3, &consumed, encoded, sizeof(encoded), &produced) == 0);
    Require(consumed == 2 && produced == 3 && std::memcmp(encoded, "\x82\xA0" "B", 3) == 0);
    const std::uint16_t utf16Source[2] = {0x3042, 0x3042};
    Require(sceCesUtf16StrGetMbcsLen(context, utf16Source, 2, &consumed, &produced) == 0 && produced == 4);
}

}

int main() {
    const void* big5 = sceCesUcsProfileInitBig5Cp950(g_big5Sheet);
    const void* sjis = sceCesUcsProfileInitSJis1997Cp932(g_sjisSheet);
    const void* eucJp = sceCesUcsProfileInitEucJpCp51932(g_eucJpSheet);
    const void* eucKr = sceCesUcsProfileInitEucKr(g_eucKrSheet);
    const void* uhc = sceCesUcsProfileInitUhc(g_uhcSheet);
    CheckBig5(big5);
    CheckJapanese(sjis, eucJp);
    CheckKorean(eucKr, uhc);
    CheckSingleByte(sceCesRefersUcsProfileCp1252());
    CheckStrings(sjis);
    return 0;
}

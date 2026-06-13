#include "eudplib_layout.h"

#include <cstring>
#include <limits>

EudplibPayloadLayout analyzeEudplibPayload(const std::vector<uint8_t>& chk) {
    EudplibPayloadLayout out;

    // STRx 섹션 찾기
    size_t pos = 0;
    size_t strxStart = std::numeric_limits<size_t>::max();
    size_t strxSize = 0;
    while (pos + 8 <= chk.size()) {
        if (std::memcmp(chk.data() + pos, "STRx", 4) == 0) {
            uint32_t sz;
            std::memcpy(&sz, chk.data() + pos + 4, 4);
            if (sz > 0x7FFFFFFFu || pos + 8 + sz > chk.size()) break;
            strxStart = pos + 8;
            strxSize = sz;
            break;
        }
        uint32_t s;
        std::memcpy(&s, chk.data() + pos + 4, 4);
        if (s > 0x7FFFFFFFu || pos + 8 + s > chk.size()) break;
        pos += 8 + s;
    }
    if (strxStart == std::numeric_limits<size_t>::max() || strxSize < 4) return out;

    out.strxChkOffset = strxStart;
    out.strxSize = strxSize;

    const uint8_t* strx = chk.data() + strxStart;

    // STRx (STR extended) header:
    //   u32 count
    //   count × u32 offsets (each is byte offset within STRx pointing to a null-terminated string)
    uint32_t count;
    std::memcpy(&count, strx, 4);
    if (count == 0 || count > 0x100000) return out;  // sanity
    size_t offsetTableSize = 4ULL + size_t(count) * 4;
    if (offsetTableSize > strxSize) return out;

    // strings 끝 위치: 모든 string offset 중 가장 큰 것 + 해당 string 의 길이 + 1 (null terminator)
    // 더 robust: offset table 안의 각 offset 을 follow 해서 string 끝 byte 위치 찾기.
    // payload 는 strings 가 끝나는 위치 + padding (4-byte 정렬) 다음 부터.
    size_t maxEnd = offsetTableSize;
    for (uint32_t i = 1; i <= count; ++i) {
        uint32_t soff;
        std::memcpy(&soff, strx + i * 4, 4);
        if (soff == 0 || soff >= strxSize) continue;
        // 해당 offset 부터 null 까지
        size_t end = soff;
        while (end < strxSize && strx[end] != 0) ++end;
        if (end < strxSize) ++end;  // include null terminator
        if (end > maxEnd) maxEnd = end;
    }

    size_t stringSectionLen = maxEnd;
    size_t strPadding = (-stringSectionLen) & 3;  // 4-byte alignment
    size_t payloadStrxOffset = stringSectionLen + strPadding;
    if (payloadStrxOffset >= strxSize) return out;

    out.stringSectionLen = stringSectionLen;
    out.strPadding = strPadding;
    out.payloadStrxOffset = payloadStrxOffset;
    out.payloadSize = strxSize - payloadStrxOffset;
    out.payloadMemoryAddr = kStrxMemoryBase + static_cast<uint32_t>(payloadStrxOffset);
    out.valid = true;
    return out;
}

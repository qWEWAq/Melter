#include "chk_parse.h"

#include <cstring>
#include <limits>

namespace {

inline uint32_t readU32LE(const uint8_t* p) {
    uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}

bool isPrintableSectionName(const uint8_t* p) {
    for (int i = 0; i < 4; ++i) {
        uint8_t c = p[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == ' ';
        if (!ok) return false;
    }
    return true;
}

}  // namespace

bool looksLikeChk(const std::vector<uint8_t>& data) {
    if (data.size() < 8) return false;
    return isPrintableSectionName(data.data()) ||
           std::memcmp(data.data(), "SMLP", 4) == 0;
}

size_t findSectionOffset(const std::vector<uint8_t>& chk, const char* name,
                         size_t& outSize) {
    outSize = 0;
    size_t pos = 0;
    while (pos + 8 <= chk.size()) {
        const uint8_t* nameBytes = chk.data() + pos;
        uint32_t size32 = readU32LE(chk.data() + pos + 4);
        if (size32 > 0x7FFFFFFFu) return std::numeric_limits<size_t>::max();
        size_t size = size32;
        if (pos + 8 + size > chk.size()) return std::numeric_limits<size_t>::max();
        if (std::memcmp(nameBytes, name, 4) == 0) {
            outSize = size;
            return pos + 8;
        }
        pos += 8 + size;
    }
    return std::numeric_limits<size_t>::max();
}

size_t findTrigSectionOffset(const std::vector<uint8_t>& chk, size_t& outPayloadSize) {
    outPayloadSize = 0;
    size_t pos = 0;
    while (pos + 8 <= chk.size()) {
        const uint8_t* nameBytes = chk.data() + pos;
        uint32_t size32 = readU32LE(chk.data() + pos + 4);
        if (size32 > 0x7FFFFFFFu) return std::numeric_limits<size_t>::max();
        size_t size = size32;
        if (pos + 8 + size > chk.size()) return std::numeric_limits<size_t>::max();

        if (std::memcmp(nameBytes, "TRIG", 4) == 0) {
            outPayloadSize = size;
            return pos + 8;
        }

        pos += 8 + size;
    }
    return std::numeric_limits<size_t>::max();
}

std::vector<uint8_t> replaceTrigSection(const std::vector<uint8_t>& chk,
                                        const std::vector<uint8_t>& newTrig) {
    size_t oldSize = 0;
    size_t payloadOffset = findTrigSectionOffset(chk, oldSize);
    if (payloadOffset == std::numeric_limits<size_t>::max()) {
        // TRIG가 없으면 원본 그대로 반환
        return chk;
    }

    // 새 헤더 size 필드를 갱신해야 함 — 페이로드 시작 -4 위치
    std::vector<uint8_t> out;
    out.reserve(chk.size() - oldSize + newTrig.size());

    // [0, payloadOffset - 4): 헤더 직전까지 그대로
    out.insert(out.end(), chk.begin(), chk.begin() + payloadOffset - 4);

    // size dword: newTrig.size()
    uint32_t newSize = static_cast<uint32_t>(newTrig.size());
    out.push_back(static_cast<uint8_t>(newSize & 0xFF));
    out.push_back(static_cast<uint8_t>((newSize >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((newSize >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((newSize >> 24) & 0xFF));

    // 새 TRIG 페이로드
    out.insert(out.end(), newTrig.begin(), newTrig.end());

    // 그 뒤 나머지 섹션들
    size_t tail = payloadOffset + oldSize;
    out.insert(out.end(), chk.begin() + tail, chk.end());

    return out;
}

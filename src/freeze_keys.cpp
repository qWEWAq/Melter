#include "freeze_keys.h"

#include <cstring>

#include "freeze_crypt.h"

bool parseFreezeKeyfile(const std::vector<uint8_t>& bytes, FreezeKeys& outKeys) {
    if (bytes.size() < 36) return false;

    for (int i = 0; i < 4; ++i) {
        std::memcpy(&outKeys.seedKey[i], bytes.data() + i * 4, 4);
    }
    for (int i = 0; i < 4; ++i) {
        std::memcpy(&outKeys.destKey[i], bytes.data() + 16 + i * 4, 4);
    }
    std::memcpy(&outKeys.fileCursor, bytes.data() + 32, 4);

    outKeys.cryptKey = computeCryptKey(outKeys.seedKey);
    return true;
}

uint32_t computeCryptKey(const uint32_t seedKey[4]) {
    uint32_t ck = 0;
    for (int i = 0; i < 4; ++i) {
        ck = freezeMix(ck, seedKey[i]);
    }
    ck = freezeMix(ck, 0);
    return ck;
}

bool parseFreezeMarker(const std::vector<uint8_t>& mpq, FreezeKeys& outKeys) {
    if (mpq.size() < 64) return false;

    // MPQ header offset 28 = blockTableEntryCount
    uint32_t blockCount;
    std::memcpy(&blockCount, mpq.data() + 28, 4);
    if (blockCount < 4) return false;

    uint64_t base = static_cast<uint64_t>(blockCount) * 16ull;
    if (base < 32 || base > mpq.size()) return false;
    size_t markerOff = static_cast<size_t>(base - 32);

    // 마커 검증: "freeze" + 2 digit ver + " protect"
    const uint8_t* m = mpq.data() + markerOff;
    if (std::memcmp(m, "freeze", 6) != 0) return false;
    if (m[6] < '0' || m[6] > '9' || m[7] < '0' || m[7] > '9') return false;
    if (std::memcmp(m + 8, " protect", 8) != 0) return false;

    // seedKey: marker - 16 .. marker
    if (markerOff < 16) return false;
    for (int i = 0; i < 4; ++i) {
        std::memcpy(&outKeys.seedKey[i], m - 16 + i * 4, 4);
    }
    // destKey: marker + 16 .. marker + 32
    if (markerOff + 32 > mpq.size()) return false;
    for (int i = 0; i < 4; ++i) {
        std::memcpy(&outKeys.destKey[i], m + 16 + i * 4, 4);
    }
    outKeys.fileCursor = 0;  // 마커에는 미저장
    outKeys.cryptKey = computeCryptKey(outKeys.seedKey);
    return true;
}

#include "freeze_decrypt.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>
#include <vector>

#include "freeze_crypt.h"

namespace {

constexpr uint32_t kTabCount = 16;     // encryptTrigger 의 tabCount
constexpr uint32_t kStride = 74;       // 2368 / 32

inline uint32_t readU32LE(const uint8_t* p) {
    uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}

inline void writeU32LE(uint8_t* p, uint32_t v) { std::memcpy(p, &v, 4); }

// 주어진 (actualKey, flag_with_high_bits) 로 wlist[16] 생성.
inline void buildWlist(uint32_t actualKey, uint32_t flagWithHigh, uint32_t wlist[kTabCount]) {
    uint32_t r = freezeMix(actualKey, flagWithHigh);
    r = freezeMix(r, actualKey);
    for (uint32_t i = 0; i < kTabCount; ++i) {
        wlist[i] = r % kStride;
        r = freezeMix(r, actualKey + i);
    }
}

// 256바이트 dword 델타 배열에 wlist 기여분 누적.
// encryption 은 (subtract reverse) 였으므로 decryption 은 (add forward).
// 순서가 (i, j) 매칭당 독립적이므로 누적 합으로 단번에 처리 가능.
inline void buildDeltas(const uint32_t wlist[kTabCount], uint32_t deltas[592]) {
    std::memset(deltas, 0, 592 * sizeof(uint32_t));
    for (uint32_t i = 0; i < kTabCount; ++i) {
        uint32_t add = freezeMix(wlist[i], i);
        uint32_t w = wlist[i];
        for (int j = 0; j < 8; ++j) {
            deltas[w] += add;
            w += kStride;
        }
    }
}

}  // namespace

bool isEncryptedTrigger(const uint8_t* trigger) {
    uint32_t flag = readU32LE(trigger + kTriggerFlagOffset);
    return (flag & 0x80000000u) != 0;
}

void decryptTriggerInPlace(uint8_t* trigger, uint32_t actualKey) {
    uint32_t flag = readU32LE(trigger + kTriggerFlagOffset);
    if (!(flag & 0x80000000u)) return;

    // SMU GetFreezeCryptFlag: (flag-0x80000000) & 0x7FFFF000 — 원래 flag 하위 12비트를
    // 마스킹해야 함. 마스킹 안 하면 trigger 의 원래 exec-flag 비트가 wlist seed 를 오염시켜
    // 정답 키로도 복호화 실패함 (이게 0/16 의 진짜 원인이었음).
    uint32_t flagWithHigh = (flag - 0x80000000u) & 0x7FFFF000u;

    uint32_t wlist[kTabCount];
    buildWlist(actualKey, flagWithHigh, wlist);

    uint32_t deltas[592];
    buildDeltas(wlist, deltas);

    // 트리거 [0, 2368) 의 dword 들에 deltas 적용
    for (uint32_t w = 0; w < 592; ++w) {
        if (deltas[w] == 0) continue;  // 미수정 위치
        uint32_t v = readU32LE(trigger + w * 4);
        writeU32LE(trigger + w * 4, v + deltas[w]);
    }

    // flag 원래 값 (low 4 bits) 복원
    writeU32LE(trigger + kTriggerFlagOffset, flag & 0xFu);
}

bool validateKeyAgainst(const uint8_t* trigger, uint32_t actualKey) {
    uint32_t flag = readU32LE(trigger + kTriggerFlagOffset);
    if (!(flag & 0x80000000u)) return true;  // 암호화 안 된 트리거면 무조건 OK

    uint32_t flagWithHigh = (flag - 0x80000000u) & 0x7FFFF000u;
    uint32_t wlist[kTabCount];
    buildWlist(actualKey, flagWithHigh, wlist);

    uint32_t deltas[592];
    buildDeltas(wlist, deltas);

    // 액션 타입 바이트만 검사하면 충분 — 트리거 전체 복호화 안 함
    // 액션 k 의 타입 바이트는 320 + k*32 + 26 byte offset.
    for (int k = 0; k < 64; ++k) {
        size_t byteOff = 320u + static_cast<size_t>(k) * 32u + 26u;
        size_t dwordIdx = byteOff / 4;       // 86, 94, 102, ...
        size_t byteInDword = byteOff % 4;    // 2, 2, 2, ... (항상 2)
        if (dwordIdx >= 592) continue;

        uint32_t decryptedDword =
            readU32LE(trigger + dwordIdx * 4) + deltas[dwordIdx];
        uint8_t actionType =
            static_cast<uint8_t>((decryptedDword >> (byteInDword * 8)) & 0xFFu);
        if (actionType > 57) return false;
    }
    return true;
}

std::vector<size_t> findEncryptedTriggers(const std::vector<uint8_t>& trigSection) {
    std::vector<size_t> out;
    size_t count = trigSection.size() / kTriggerSize;
    for (size_t i = 0; i < count; ++i) {
        const uint8_t* t = trigSection.data() + i * kTriggerSize;
        if (isEncryptedTrigger(t)) out.push_back(i);
    }
    return out;
}

int decryptAllTriggers(std::vector<uint8_t>& trigSection, uint32_t actualKey) {
    int n = 0;
    size_t count = trigSection.size() / kTriggerSize;
    for (size_t i = 0; i < count; ++i) {
        uint8_t* t = trigSection.data() + i * kTriggerSize;
        if (isEncryptedTrigger(t)) {
            decryptTriggerInPlace(t, actualKey);
            ++n;
        }
    }
    return n;
}

BruteForceResult bruteForceTriggerKey(
    const std::vector<const uint8_t*>& encryptedTriggers, uint32_t cryptKey,
    int threadCount) {
    BruteForceResult result;
    if (encryptedTriggers.empty()) return result;

    if (threadCount <= 0) {
        threadCount = static_cast<int>(std::thread::hardware_concurrency());
        if (threadCount <= 0) threadCount = 1;
    }

    auto t0 = std::chrono::steady_clock::now();

    std::atomic<bool> found{false};
    std::atomic<uint32_t> foundTriggerKey{0};
    std::atomic<uint32_t> foundActualKey{0};
    std::atomic<uint64_t> totalTried{0};

    auto worker = [&](uint64_t startCandidate, uint64_t step) {
        uint64_t triedLocal = 0;
        for (uint64_t cand = startCandidate; cand < (1ULL << 32); cand += step) {
            if (found.load(std::memory_order_relaxed)) break;
            uint32_t triggerKey = static_cast<uint32_t>(cand);
            uint32_t actualKey = freezeMix(triggerKey, cryptKey);

            // 첫 트리거로 빠른 1차 필터
            if (!validateKeyAgainst(encryptedTriggers[0], actualKey)) {
                ++triedLocal;
                if ((triedLocal & 0xFFFFFFULL) == 0) {
                    totalTried.fetch_add(triedLocal, std::memory_order_relaxed);
                    triedLocal = 0;
                }
                continue;
            }

            // 나머지 트리거들로 교차 검증
            bool allPass = true;
            for (size_t k = 1; k < encryptedTriggers.size(); ++k) {
                if (!validateKeyAgainst(encryptedTriggers[k], actualKey)) {
                    allPass = false;
                    break;
                }
            }

            if (allPass) {
                bool expected = false;
                if (found.compare_exchange_strong(expected, true)) {
                    foundTriggerKey.store(triggerKey, std::memory_order_relaxed);
                    foundActualKey.store(actualKey, std::memory_order_relaxed);
                }
                totalTried.fetch_add(triedLocal + 1, std::memory_order_relaxed);
                return;
            }
            ++triedLocal;
        }
        totalTried.fetch_add(triedLocal, std::memory_order_relaxed);
    };

    std::vector<std::thread> threads;
    threads.reserve(threadCount);
    for (int t = 0; t < threadCount; ++t) {
        threads.emplace_back(worker, static_cast<uint64_t>(t),
                             static_cast<uint64_t>(threadCount));
    }
    for (auto& th : threads) th.join();

    auto t1 = std::chrono::steady_clock::now();
    result.elapsedSeconds = std::chrono::duration<double>(t1 - t0).count();
    result.candidatesTried = totalTried.load();
    result.found = found.load();
    if (result.found) {
        result.triggerKey = foundTriggerKey.load();
        result.actualKey = foundActualKey.load();
    }
    return result;
}

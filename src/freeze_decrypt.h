#ifndef MELTER_FREEZE_DECRYPT_H
#define MELTER_FREEZE_DECRYPT_H

#include <cstdint>
#include <vector>

// 한 트리거 = 2400 바이트.
constexpr size_t kTriggerSize = 2400;

// flag dword 의 오프셋 (트리거 안에서).
constexpr size_t kTriggerFlagOffset = 2368;

// 암호화된 트리거인지 검사 — flag dword 의 최상위 비트가 set 이면 true.
bool isEncryptedTrigger(const uint8_t* trigger);

// 단일 트리거를 in-place 복호화.
//   actualKey = mix2(triggerKey, cryptKey)
// 호출 전 isEncryptedTrigger 로 확인할 것 (이 함수는 무조건 적용).
void decryptTriggerInPlace(uint8_t* trigger, uint32_t actualKey);

// 모든 암호화된 트리거를 in-place 복호화.
// 반환값: 복호화된 트리거 수.
int decryptAllTriggers(std::vector<uint8_t>& trigSection, uint32_t actualKey);

// TRIG 섹션 안에서 암호화된 트리거 인덱스들을 수집.
std::vector<size_t> findEncryptedTriggers(const std::vector<uint8_t>& trigSection);

// 후보 키로 한 트리거를 복호화한 뒤 모든 액션 타입 바이트가 <= 57 인지 검증.
// 사본을 떠서 검사하므로 입력은 변경되지 않는다.
bool validateKeyAgainst(const uint8_t* trigger, uint32_t actualKey);

// triggerKey brute-force.
//   - encryptedTriggers: 검증에 쓸 암호화 트리거들 (3개면 충분)
//   - cryptKey: seedKey 로부터 계산된 값
//   - threadCount: 0 이면 hardware_concurrency
// 반환값:
//   성공시: 회수된 triggerKey (raw 값, mix2(triggerKey, cryptKey) 가 실제 키)
//   실패시: false 반환되고 outTriggerKey 미정의
//
// 진행상황은 progressCallback 으로 보고 (cancellable: callback이 false 반환시 중단).
struct BruteForceResult {
    bool found = false;
    uint32_t triggerKey = 0;   // raw triggerKeyVal
    uint32_t actualKey = 0;    // mix2(triggerKey, cryptKey) — 실제 해독 키
    double elapsedSeconds = 0;
    uint64_t candidatesTried = 0;
};

BruteForceResult bruteForceTriggerKey(
    const std::vector<const uint8_t*>& encryptedTriggers,
    uint32_t cryptKey,
    int threadCount = 0);

#endif  // MELTER_FREEZE_DECRYPT_H

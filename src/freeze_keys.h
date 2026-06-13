#ifndef MELTER_FREEZE_KEYS_H
#define MELTER_FREEZE_KEYS_H

#include <cstdint>
#include <vector>

// (keyfile) 36바이트로부터 freeze 키 회수.
struct FreezeKeys {
    uint32_t seedKey[4]   = {0, 0, 0, 0};
    uint32_t destKey[4]   = {0, 0, 0, 0};
    uint32_t fileCursor   = 0;

    // seedKey 로부터 결정적으로 계산되는 cryptKey.
    uint32_t cryptKey     = 0;
};

// (keyfile) 의 36바이트를 파싱. 길이가 36 미만이면 실패.
// 반환값: 성공시 true, keys 채워짐.
bool parseFreezeKeyfile(const std::vector<uint8_t>& keyfileBytes, FreezeKeys& outKeys);

// MPQ 파일 raw bytes 에서 freeze 마커 옆에 박힌 seedKey/destKey 추출.
//   marker = file offset = blockCount*16 - 32 의 16 바이트 ("freezeXX protect")
//   seedKey = marker - 16 .. marker
//   destKey = marker + 16 .. marker + 32
// (keyfile) MPQ 엔트리가 제거된 보호 맵에서도 키 회수 가능. fileCursor 는 미회수.
bool parseFreezeMarker(const std::vector<uint8_t>& mpqRaw, FreezeKeys& outKeys);

// seedKey 로부터 cryptKey 계산:
//   cryptKey = 0
//   for sk in seedKey: cryptKey = mix2(cryptKey, sk)
//   cryptKey = mix2(cryptKey, 0)
uint32_t computeCryptKey(const uint32_t seedKey[4]);

#endif  // MELTER_FREEZE_KEYS_H

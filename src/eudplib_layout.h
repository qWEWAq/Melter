#ifndef MELTER_EUDPLIB_LAYOUT_H
#define MELTER_EUDPLIB_LAYOUT_H

// eudplib payload 의 메모리 레이아웃 분석.
// src/eudplib/maprw/injector/payload_init.py 의 알고리즘을 그대로 적용:
//
//   STRx 섹션 = [string section bytes] + [str_padding (≤3 bytes)] + [payload bytes]
//   payload 는 메모리 주소 0x191943C8 + len(string_section) + str_padding 에 로드됨
//
// 우리 emulator 에서:
//   - VMemory 의 그 주소에 payload bytes 를 매핑
//   - 그러면 EUDObject EPDs 가 정확히 그 메모리 영역을 가리킴
//   - PTS chain 이 nextptr 따라 payload 트리거를 실행할 수 있음

#include <cstdint>
#include <cstddef>
#include <vector>

// STRx 의 Storm 메모리 base address (eudplib 의 magic).
constexpr uint32_t kStrxMemoryBase = 0x191943C8u;

struct EudplibPayloadLayout {
    bool valid = false;

    // chk 안의 STRx 섹션 시작 byte offset (header 8 byte 직후의 payload data)
    size_t strxChkOffset = 0;
    size_t strxSize = 0;

    // STRx 안에서 strings 섹션의 byte 길이 (offset table + null-terminated strings)
    size_t stringSectionLen = 0;
    size_t strPadding = 0;

    // STRx 안에서 payload 가 시작하는 byte offset (= stringSectionLen + strPadding)
    size_t payloadStrxOffset = 0;
    size_t payloadSize = 0;

    // payload 가 SC 메모리에 로드되는 주소
    uint32_t payloadMemoryAddr = 0;
};

// chk 의 STRx 섹션을 분석해서 payload 위치와 메모리 주소 계산.
EudplibPayloadLayout analyzeEudplibPayload(const std::vector<uint8_t>& chk);

#endif

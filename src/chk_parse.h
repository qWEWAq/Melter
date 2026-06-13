#ifndef MELTER_CHK_PARSE_H
#define MELTER_CHK_PARSE_H

#include <cstdint>
#include <string>
#include <vector>

// CHK 안의 TRIG 섹션 위치를 찾는다.
// 같은 이름의 섹션이 여러 개 있으면 첫 번째.
// 반환값: TRIG 페이로드 시작 byte offset (헤더 다음). 못 찾으면 SIZE_MAX.
size_t findTrigSectionOffset(const std::vector<uint8_t>& chk, size_t& outPayloadSize);

// CHK의 TRIG 페이로드를 새 데이터로 교체한 결과를 반환.
// 새 데이터의 크기가 다르면 그 다음 섹션들의 위치도 자동 이동.
std::vector<uint8_t> replaceTrigSection(const std::vector<uint8_t>& chk,
                                        const std::vector<uint8_t>& newTrig);

// CHK 전체 검증 — 적어도 한 섹션이 파싱 가능하면 true.
bool looksLikeChk(const std::vector<uint8_t>& data);

// 임의 section 의 byte offset + size. 못 찾으면 SIZE_MAX.
size_t findSectionOffset(const std::vector<uint8_t>& chk, const char* name,
                         size_t& outSize);

#endif  // MELTER_CHK_PARSE_H

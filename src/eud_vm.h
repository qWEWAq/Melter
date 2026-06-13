#ifndef MELTER_EUD_VM_H
#define MELTER_EUD_VM_H

// EUD VM — eudplib 의 핵심 메커니즘 (VProc, SetDeathsX mask, EUDVariable 발화) 을 emulate.
//
// 이전 trig_emulate.h 의 단순 dispatch 위에 다음을 추가:
//   1) Mask + modifier 의 정확한 조합 처리
//      mem = (mem & ~mask) | (op(mem, value) & mask)
//   2) EUDVariable 슬롯 추적
//      chk 안의 EUDVarBuffer 자동 탐색 + 슬롯별 (MASK, DEST, VALUE) 위치 등록
//   3) Trigger Template 발화
//      한 trigger 의 action[0] 이 다른 trigger 의 action 필드 (MASK/DEST/VALUE) 를 수정
//      한 뒤 그 trigger 의 nextptr 로 점프 → 수정된 template 이 발화 → write
//   4) Memory() 조건 정확 처리
//
// 출처: docs/eudplib.md

#include <cstdint>
#include <vector>

class VMemory;

namespace eud {

// EUDVariable 의 메모리 슬롯 (chk 내 발견된 EUDVarBuffer 의 한 칸).
//   each slot is 72 bytes
//   value 는 slot+348 (= action[0] 의 player2 위치)
//   dest  는 slot+344 (= action[0] 의 player1 위치)
//   mask  는 slot+328 (= action[0] 의 locID 위치)
//   modifier 는 slot+355 (= action[0] 의 modifier 위치)
struct VarSlot {
    uint32_t base;        // slot 시작 주소 (chk 안의 위치 → 메모리 주소)
    uint32_t valueAddr;   // base + 348
    uint32_t destAddr;    // base + 344
    uint32_t maskAddr;    // base + 328
    uint32_t modifierAddr;// base + 355 (1 byte)
};

// chk 페이로드에서 EUDVarBuffer 들을 자동 탐색.
// 패턴: 72byte 간격으로 ['\xFF\xFF\xFF\xFF...][...][0x00 0x00 0x2D 0x07 ...SC...]'.
// chk 안의 byte offset 을 (mapped) memory address 로 변환하려면 chkBaseAddr 가 필요.
//
// 반환: 발견된 VarSlot 목록 (메모리 주소 기준).
std::vector<VarSlot> findEudVarSlots(const std::vector<uint8_t>& chkPayload,
                                      uint32_t chkBaseAddr);

// SetDeathsX 적용:
//   mem = (mem & ~mask) | (apply_modifier(mem, value, modifier) & mask)
//
// modifier:
//   7 = SetTo
//   8 = Add
//   9 = Subtract
uint32_t applyMaskedOp(uint32_t current, uint8_t modifier, uint32_t value, uint32_t mask);

// VarSlot 의 action[0] 발화 — slot 자체가 trigger 이므로 호출하면
// (dest, mask, modifier, value) 가 적용됨.
// VMemory 에서 slot 의 현재 (dest, mask, modifier, value) 를 읽어 실행.
void fireVarAction(VMemory& mem, const VarSlot& slot);

}  // namespace eud

#endif

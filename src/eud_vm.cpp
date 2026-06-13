#include "eud_vm.h"

#include <cstring>

#include "vmemory.h"

namespace eud {

// EUDVarBuffer 의 magic 패턴 (72byte 슬롯 시작 부근):
//   offset 0..3:    0xFF 0xFF 0xFF 0xFF      (nextptr marker = 0xFFFFFFFF)
//   offset 24:      0x00 0x00 0x2D 0x07      (action header: 0x2D=45 acttype, 0x07=SetTo modifier)
//   offset 30..31:  'S' 'C'                  (EUDx = 0x4353 SetMemory marker)
//   offset 32:      0x04                     (currentAction)
//
// 단, 컴파일된 버전에 따라 modifier 가 SetTo 가 아닐 수 있음 (Add/Sub 도 가능).
// 일관성 있는 부분: 0xFF.. nextptr + 'SC' marker.
//
// 슬롯들이 72byte 간격으로 연속 → 첫 슬롯 발견 후 이후 패턴 검증.
static bool looksLikeVarSlot(const uint8_t* p, size_t remaining) {
    if (remaining < 72) return false;
    // nextptr = 0xFFFFFFFF
    if (p[0] != 0xFF || p[1] != 0xFF || p[2] != 0xFF || p[3] != 0xFF) return false;
    // 'SC' marker at +30,31 (action[0].EUDx in chk action format)
    // action[0] 은 슬롯 +328 부터지만, 72byte 압축형이므로 다른 위치에 있을 수 있음
    // 안전한 검출: 'SC' 가 슬롯 처음 72byte 안에 있는지
    bool foundSC = false;
    for (size_t i = 0; i + 1 < 72 && i + 1 < remaining; ++i) {
        if (p[i] == 'S' && p[i + 1] == 'C') {
            foundSC = true;
            break;
        }
    }
    if (!foundSC) return false;
    // acttype 0x2D 가 있는지
    bool foundActtype = false;
    for (size_t i = 0; i < 72 && i < remaining; ++i) {
        if (p[i] == 0x2D) { foundActtype = true; break; }
    }
    return foundActtype;
}

std::vector<VarSlot> findEudVarSlots(const std::vector<uint8_t>& chk,
                                      uint32_t chkBaseAddr) {
    std::vector<VarSlot> out;
    if (chk.size() < 72) return out;
    // 첫 슬롯 후보 찾기: 4byte 정렬로 슬라이딩하면서 looksLikeVarSlot 검사
    for (size_t off = 0; off + 72 <= chk.size(); off += 4) {
        if (!looksLikeVarSlot(chk.data() + off, chk.size() - off)) continue;
        // 다음 슬롯도 같은 패턴이면 buffer 확정
        if (off + 144 > chk.size()) continue;
        if (!looksLikeVarSlot(chk.data() + off + 72, chk.size() - off - 72)) continue;

        // 연속된 슬롯들을 다 수집
        size_t cur = off;
        while (cur + 72 <= chk.size() &&
               looksLikeVarSlot(chk.data() + cur, chk.size() - cur)) {
            VarSlot s;
            s.base = chkBaseAddr + static_cast<uint32_t>(cur);
            // action[0] 은 slot+8+320 = slot+328 (full trigger 가정)
            // 단 72byte 압축에선 action 위치가 다를 수 있음 — 위치는 base+offset_of_action.
            // 보수적으로 표준 위치 (full trigger 패턴) 사용
            s.maskAddr     = s.base + 328;
            s.destAddr     = s.base + 344;
            s.valueAddr    = s.base + 348;
            s.modifierAddr = s.base + 355;
            out.push_back(s);
            cur += 72;
        }
        // skip past this buffer
        if (cur > off) {
            off = cur - 4;  // for() 가 += 4 할 거니까
        }
    }
    return out;
}

uint32_t applyMaskedOp(uint32_t current, uint8_t modifier, uint32_t value, uint32_t mask) {
    uint32_t opResult;
    switch (modifier) {
        case 7:  opResult = value; break;             // SetTo
        case 8:  opResult = current + value; break;    // Add
        case 9:  opResult = current - value; break;    // Subtract
        default: opResult = current; break;
    }
    return (current & ~mask) | (opResult & mask);
}

void fireVarAction(VMemory& mem, const VarSlot& slot) {
    // slot 의 현재 action[0] 필드 읽기
    uint32_t mask;
    uint32_t dest;
    uint32_t value;
    uint8_t  modifier;
    try {
        mask     = mem.readU32(slot.maskAddr);
        dest     = mem.readU32(slot.destAddr);
        value    = mem.readU32(slot.valueAddr);
        modifier = mem.readU8(slot.modifierAddr);
    } catch (...) {
        return;
    }
    // dest 는 EPD-인코딩된 메모리 dword 위치 → 실제 주소
    // EPD == (addr - 0x58A364) / 4 → addr = 0x58A364 + EPD * 4
    uint32_t addr = 0x58A364u + dest * 4u;
    uint32_t current;
    try { current = mem.readU32(addr); } catch (...) { current = 0; }
    uint32_t result = applyMaskedOp(current, modifier, value, mask);
    try { mem.writeU32(addr, result); } catch (...) {}
}

}  // namespace eud

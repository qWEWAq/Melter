#ifndef MELTER_SC_MEMORY_LAYOUT_H
#define MELTER_SC_MEMORY_LAYOUT_H

// StarCraft 1.16.1 의 알려진 정적 메모리 주소들.
// EUD 트리거가 직접 접근하는 주요 영역.
//
// 출처: 이전 mpqtrig 의 trigEmulate.cpp 및 euddraft/freeze 소스.

#include <cstdint>

namespace sc {

// ─────────── 유닛/플레이어 정보 ───────────
constexpr uint32_t UnitInfoTable        = 0x5193A0;  // 12 × 228
constexpr uint32_t PlayerTrigStructBase = 0x51A280;  // 12 × 8 (PTS)
constexpr uint32_t DeathTable           = 0x58A364;  // 48 × 228 (player × unit)
constexpr uint32_t LocationTable        = 0x58D740;  // 20 × 64 (vanilla locations)
constexpr uint32_t SwitchTable          = 0x58DC40;  // 32 × 1
constexpr uint32_t MRGNTable            = 0x58DC60;  // 20 × 255

// ─────────── chk 섹션 포인터 ───────────
constexpr uint32_t MtxmPointer          = 0x5993C4;  // 4 bytes
constexpr uint32_t StrTablePointer      = 0x5993D4;  // 4 bytes (STR or STRx)
constexpr uint32_t UnitNodeTable        = 0x59CCA8;  // 571200 bytes

// ─────────── 게임 상태 ───────────
constexpr uint32_t CurrentPlayer        = 0x6509B0;  // 4 bytes
constexpr uint32_t NetworkBuffer        = 0x654880;  // 496 bytes
constexpr uint32_t TranWireGrpPtr       = 0x68C1F4;  // 4 bytes
constexpr uint32_t GrpWireGrpPtr        = 0x68C1FC;
constexpr uint32_t WireframeGrpPtr      = 0x68C204;

// ─────────── 옛 코드와 동일 추가 mock regions ───────────
constexpr uint32_t GameTick             = 0x57F23C;  // 4 bytes
constexpr uint32_t LocalNationId        = 0x512684;  // 4 bytes
constexpr uint32_t NextUnitPtr          = 0x628438;  // 4 bytes → 0x59CCA8
constexpr uint32_t DisplayTextBuffer    = 0x6413E4;  // 218*12 bytes
constexpr uint32_t BwTechAvailable      = 0x58F050;  // 20*12 bytes
constexpr uint32_t BwTechResearched     = 0x58F140;  // 20*12 bytes
constexpr uint32_t BwUpgradesResearched = 0x58F32C;  // 15*12 bytes
constexpr uint32_t BwUpgradesAvailable  = 0x58F278;  // 15*12 bytes

// ─────────── replay / freeze keycalc 관련 ───────────
constexpr uint32_t ReplayHeader         = 0x6D0F30;  // 633 bytes
constexpr uint32_t IsReplayFlag         = 0x6D0F14;  // 4 bytes (freeze keycalc 검사)

// ─────────── Storm 동적 주소 (freeze keycalc 에서 필요) ───────────
//   0x4FE544       : SStrLen import — Storm 베이스 주소 재배치용
//   0x1505ADFC     : Map handle EPD slot (Storm 안의 슬롯; 베이스 재배치 영향 받음)
constexpr uint32_t StormSStrLenImport   = 0x4FE544;
constexpr uint32_t StormMapHandleSlot   = 0x1505ADFC;
constexpr uint32_t StormBaseExpected    = 0x15021A00;

// ─────────── EUD 트리거 데이터 영역 (우리가 임의 배치) ───────────
//   TRIG 섹션 자체를 메모리에 놓을 가상 주소.
constexpr uint32_t TrigSectionAlloc     = 0x20000000;
constexpr uint32_t StrxSectionAlloc     = 0x191943C8;

}  // namespace sc

#endif  // MELTER_SC_MEMORY_LAYOUT_H

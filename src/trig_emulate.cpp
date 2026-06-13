#include "trig_emulate.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>

#include "chk_parse.h"
#include "debug_log.h"
#include "sc_memory_layout.h"

void parseEmTrigger(const uint8_t* bytes, EmTrigger& out) {
    out.rawBytes = bytes;
    // 16 conditions × 20 bytes
    for (int i = 0; i < 16; ++i) {
        const uint8_t* c = bytes + i * 20;
        std::memcpy(&out.conditions[i].locID,      c + 0, 4);
        std::memcpy(&out.conditions[i].player,     c + 4, 4);
        std::memcpy(&out.conditions[i].amount,     c + 8, 4);
        std::memcpy(&out.conditions[i].unitID,     c + 12, 2);
        out.conditions[i].comparison = c[14];
        out.conditions[i].condtype   = c[15];
        out.conditions[i].restype    = c[16];
        out.conditions[i].flag       = c[17];
        std::memcpy(&out.conditions[i].eudx,       c + 18, 2);
    }
    // 64 actions × 32 bytes at offset 320
    for (int i = 0; i < 64; ++i) {
        const uint8_t* a = bytes + 320 + i * 32;
        std::memcpy(&out.actions[i].locID,    a + 0, 4);
        std::memcpy(&out.actions[i].strID,    a + 4, 4);
        std::memcpy(&out.actions[i].wavID,    a + 8, 4);
        std::memcpy(&out.actions[i].time,     a + 12, 4);
        std::memcpy(&out.actions[i].player1,  a + 16, 4);
        std::memcpy(&out.actions[i].player2,  a + 20, 4);
        std::memcpy(&out.actions[i].unitID,   a + 24, 2);
        out.actions[i].acttype   = a[26];
        out.actions[i].modifier  = a[27];
        out.actions[i].flags     = a[28];
        out.actions[i].internal1 = a[29];
        std::memcpy(&out.actions[i].eudx,     a + 30, 2);
        out.actions[i].mask = out.actions[i].eudx;  // 같은 자리, 의미적 alias
    }
    std::memcpy(&out.flag, bytes + 2368, 4);
    std::memcpy(out.effPlayer, bytes + 2372, 28);
}

TrigEmulator::TrigEmulator(VMemory& mem) : mem_(mem) {
    buildDispatchTables();
}

void TrigEmulator::buildDispatchTables() {
    // ─────────── 조건 dispatch (condtype 0..23) ───────────
    // 기본: TRUE 반환 (게임 상태 의존 조건은 일단 만족된 것으로 보고 액션 실행)
    // 그래야 assigner / decryptTrigger flow 가 진행됨.
    for (int i = 0; i < 24; ++i) condTable_[i] = &TrigEmulator::cond_TrueByDefault;
    condTable_[0]  = &TrigEmulator::cond_Empty;     // 빈 슬롯
    condTable_[15] = &TrigEmulator::cond_Deaths;    // Deaths / DeathsX / Memory (EUDx 로 구분)
    condTable_[22] = &TrigEmulator::cond_Always;
    condTable_[23] = &TrigEmulator::cond_Never;

    // ─────────── 액션 dispatch (acttype 0..63) ───────────
    // 기본: Noop (게임에 영향 안 줌)
    for (int i = 0; i < 64; ++i) actTable_[i] = &TrigEmulator::act_Noop;
    actTable_[0]  = &TrigEmulator::act_Noop;             // No action
    actTable_[3]  = &TrigEmulator::act_PreserveTrigger;  // PreserveTrigger
    actTable_[13] = &TrigEmulator::act_SetSwitch;        // SetSwitch (EUD trick)
    actTable_[14] = &TrigEmulator::act_SetCountdownTimer;// SetCountdownTimer (EUD trick)
    actTable_[26] = &TrigEmulator::act_SetResources;     // SetResources (EUD trick)
    actTable_[27] = &TrigEmulator::act_SetScore;         // SetScore (EUD trick)
    actTable_[45] = &TrigEmulator::act_SetDeathsLike;    // SetDeaths / SetDeathsX / SetMemory / SetKills
    actTable_[47] = &TrigEmulator::act_Comment;          // Comment
}

void TrigEmulator::initStaticAreas() {
    // SC 가 가지고 있는 주요 메모리 영역들을 미리 할당.
    // 크기는 mpqtrig 의 기존 값 + 정렬.
    mem_.allocAt(sc::UnitInfoTable,        12 * 228, "UnitInfo");
    mem_.allocAt(sc::PlayerTrigStructBase, 12 * 8,   "PTS");
    mem_.allocAt(sc::DeathTable,           48 * 228, "DeathTable");
    mem_.allocAt(sc::LocationTable,        20 * 64,  "LocationTable");
    mem_.allocAt(sc::SwitchTable,          32 * 1,   "SwitchTable");
    mem_.allocAt(sc::MRGNTable,            20 * 255, "MRGN");
    mem_.allocAt(sc::MtxmPointer,          4,        "MtxmPtr");
    mem_.allocAt(sc::StrTablePointer,      4,        "StrPtr");
    // 옛 코드 line 379 — STR pointer = STRx address (= 0x191943C8)
    mem_.writeU32(sc::StrTablePointer, sc::StrxSectionAlloc);
    mem_.allocAt(sc::UnitNodeTable,        571200,   "UnitNode");
    mem_.allocAt(sc::CurrentPlayer,        4,        "CurrentPlayer");
    mem_.allocAt(sc::NetworkBuffer,        496,      "NetworkBuffer");
    mem_.allocAt(sc::TranWireGrpPtr,       4,        "TranWireGrpPtr");
    mem_.allocAt(sc::GrpWireGrpPtr,        4,        "GrpWireGrpPtr");
    mem_.allocAt(sc::WireframeGrpPtr,      4,        "WireframeGrpPtr");
    mem_.allocAt(sc::ReplayHeader,         633,      "ReplayHeader");
    // IsReplayFlag(0x6D0F14) + 28 bytes 의 ReplayState 영역 확장 매핑.
    // 원래 4 bytes 였는데 freeze 가 0x6D0F18 부터 폴링하므로 더 크게.
    mem_.allocAt(sc::IsReplayFlag,         28,       "ReplayState");

    // ReplayFlag = 0 으로 — freeze 의 keycalc 가 "게임 모드" 분기 타도록
    mem_.writeU32(sc::IsReplayFlag, 0);

    // 0x6D0F18 = SC frame tick counter. 실제 게임처럼 0 으로 시작.
    // EUDDoEvents polling 자연 fail → chain yield → multi-frame loop 가능.
    mem_.writeU32(sc::IsReplayFlag + 4, 0);
    mem_.writeU32(sc::IsReplayFlag + 8, 0);
    mem_.writeU32(sc::IsReplayFlag + 12, 0);

    // 0x6D0F14 부터 64 바이트 (= IsReplayFlag + 주변 ReplayState 영역) 확장 매핑.
    // freeze 가 0x6D0F18 부터 폴링하는 게 strict cond 모드에서 확인됨.
    // 기존 IsReplayFlag 의 4바이트만 매핑됐던 걸 64바이트로.
    // 우선 모두 0 으로 채움 (실제 SC 값 모름).

    // NULL region (= 0x0 부터 4KB) — eudplib 의 일부 코드가 NULL deref (= 0 영역 read).
    //   진짜 SC 의 NULL page 도 0 으로 채워짐 (= 안전 read).
    mem_.allocAt(0, 0x1000, "NULL-page");

    // FIX: 광역 SC engine memory mock — EPD trick self-consistency.
    // 알려진 큰 gap 들 채우기 (기존 SC alloc 영역 사이의 빈 공간)
    try { mem_.allocAt(0x00400000, 0x4FE000 - 0x400000, "gap1"); } catch (...) {}
    try { mem_.allocAt(0x004FE600, 0x512000 - 0x4FE600, "gap2"); } catch (...) {}
    try { mem_.allocAt(0x00512700, 0x519000 - 0x512700, "gap3"); } catch (...) {}
    try { mem_.allocAt(0x0051B000, 0x57F000 - 0x51B000, "gap4"); } catch (...) {}
    try { mem_.allocAt(0x0057F300, 0x58A000 - 0x57F300, "gap5"); } catch (...) {}
    try { mem_.allocAt(0x0058D000, 0x58D700 - 0x58D000, "gap6"); } catch (...) {}
    try { mem_.allocAt(0x0058F400, 0x599000 - 0x58F400, "gap7"); } catch (...) {}
    try { mem_.allocAt(0x00599400, 0x59CC00 - 0x599400, "gap8"); } catch (...) {}
    try { mem_.allocAt(0x00629000, 0x641000 - 0x629000, "gap9"); } catch (...) {}
    try { mem_.allocAt(0x00642000, 0x650000 - 0x642000, "gap10"); } catch (...) {}
    try { mem_.allocAt(0x00651000, 0x654000 - 0x651000, "gap11"); } catch (...) {}
    try { mem_.allocAt(0x00655000, 0x68C000 - 0x655000, "gap12"); } catch (...) {}
    try { mem_.allocAt(0x0068D000, 0x6D0000 - 0x68D000, "gap13"); } catch (...) {}
    try { mem_.allocAt(0x006D2000, 0x900000 - 0x6D2000, "gap14"); } catch (...) {}

    // eud-book.dev 에서 발견된 SC structures (우리가 빠뜨린 것들)
    // 0x005C0000 영역 = iscript + dat data pointers + CP Trick + Replay header
    try { mem_.allocAt(0x005C0000, 0x2000, "SCdat-block"); } catch (...) {}
    // 0x00512800 = Trigger Action Function Array (60 × 4)
    try { mem_.allocAt(0x00512800, 240, "TrigActFnArray"); } catch (...) {}
    // 0x00515A98 = Trigger Condition Function Array (24 × 4)
    try { mem_.allocAt(0x00515A98, 96, "TrigCondFnArray"); } catch (...) {}
    // 0x00598250 = Sprite Table + CSprite
    try { mem_.allocAt(0x00598250, 64, "SpriteTable"); } catch (...) {}
    // 0x005C1050 = Trigger Current Player (CP Trick 의 진짜 위치!)
    // (이미 SCdat-block 안에 포함되어 있음)
    // EPD trick high mem target — mock alloc 만 (0 init), 진짜 SC 값 없으니 의미 없음
    try { mem_.allocAt(0xFC000000, 0x01000000, "EPD-high"); } catch (...) {}
    try { mem_.allocAt(0x4BC00000, 0x00200000, "EPD-mid"); } catch (...) {}
    // ───── 옛 코드와 동일 추가 mock regions ─────
    mem_.allocAt(sc::GameTick, 4, "GameTick");
    mem_.writeU32(sc::GameTick, 0);
    mem_.allocAt(sc::LocalNationId, 4, "LocalNationId");
    mem_.writeU32(sc::LocalNationId, 0);
    mem_.allocAt(sc::NextUnitPtr, 4, "NextUnitPtr");
    mem_.writeU32(sc::NextUnitPtr, sc::UnitNodeTable);  // 옛 코드: 0x59CCA8
    mem_.allocAt(sc::DisplayTextBuffer, 218 * 12, "DisplayTextBuffer");
    mem_.allocAt(sc::BwTechAvailable, 20 * 12, "BwTechAvailable");
    mem_.allocAt(sc::BwTechResearched, 20 * 12, "BwTechResearched");
    mem_.allocAt(sc::BwUpgradesResearched, 15 * 12, "BwUpgradesResearched");
    mem_.allocAt(sc::BwUpgradesAvailable, 15 * 12, "BwUpgradesAvailable");

    // ───── Storm.dll 모킹 (keycalc 가 MPQ data 읽으려고 이걸 통해 베이스 주소 가져옴) ─────
    mem_.allocAt(sc::StormSStrLenImport, 4, "StormSStrLen");
    // SStrLen import value: should be EXACTLY sc::StormBaseExpected = 0x15021A00
    // so that eudplib's stormRelocateAmount = (SStrLen - 0x15021A00) // 4 = 0.
    // Previously had + 0x1000 (= 0x15022A00), which gave stormRelocateAmount = 0x400,
    // causing getMapHandleEPD to read at WRONG address (0x1505BEFC instead of 0x1505ADFC).
    mem_.writeU32(sc::StormSStrLenImport, sc::StormBaseExpected);

    // Storm 영역 — 4MB. MapHandle slot 포함.
    constexpr uint32_t kStormSize = 0x400000;  // 4MB
    mem_.allocAt(sc::StormBaseExpected, kStormSize, "StormDll");

    // MapHandle 슬롯은 Storm region 안에 있으므로 별도 alloc 불필요. 그냥 write.
    mem_.writeU32(sc::StormMapHandleSlot, sc::StormBaseExpected);

    // high-mem (≥0x80000000) IAT thunk 영역은 cond_Deaths 의 auto-mock 에서 처리.
    // 여기서 미리 매핑하지 않음 (auto-mock 가 못 실행됨).
}

// EPD 변환 헬퍼 — 주어진 mem address → DeathTable 기준 EPD value
static inline uint32_t EPDof(uint32_t addr) {
    return (addr - 0x58A364u) / 4u;
}

void TrigEmulator::mockStormMpqHandle(
    const uint8_t* mpqHeader32,
    const std::vector<HashTableEntry>& decryptedHashTable,
    const std::vector<BlockTableEntry>& decryptedBlockTable,
    const std::vector<uint8_t>& rawMpqBytes) {
    // 옛 코드 layout — stormBase=0x16000000 (RAW), mpqData=0x60000000 (RAW 연속).
    constexpr uint32_t kStormBaseAddr = 0x16000000u;  // MapHandle (Storm 내부)
    constexpr uint32_t kMapHandleAddr = kStormBaseAddr;  // 옛 코드와 동일
    constexpr uint32_t kMpqHeaderAddr = 0x60000000u;     // mpqDataAddr
    uint32_t blockTableBytes = (uint32_t)(decryptedBlockTable.size() * sizeof(BlockTableEntry));
    uint32_t hashTableBytes  = (uint32_t)(decryptedHashTable.size() * sizeof(HashTableEntry));
    const uint32_t kBlockTableAddr = kMpqHeaderAddr + 0x20;                       // 연속!
    const uint32_t kHashTableAddr  = kMpqHeaderAddr + 0x20 + blockTableBytes;     // 연속!
    const uint32_t kRawMpqAddr     = kMpqHeaderAddr + 0x20 + blockTableBytes + hashTableBytes;

    // 1) Storm SStrLen import — eudplib calculates:
    //    stormRelocateAmount = (SStrLen - 0x15021A00) // 4
    //    For 0 relocation, SStrLen must EQUAL 0x15021A00.
    mem_.writeU32(sc::StormSStrLenImport, sc::StormBaseExpected);  // (will be overwritten by mockStormMpqHandle)

    // 1b) getMapHandleEPD 진입점 0x4FE304 mock
    //   keycalc 가:  stormRelocateAmount = f_epdread_epd(EPD(0x4FE304))
    //               stormRelocateAmount += EPD(MapHandleSlot) - EPD(StormBase) = 0xE4FF
    //               return f_epdread_epd(stormRelocateAmount)  → dword at MapHandleSlot
    //   따라서 0x4FE304 의 dword (EPD 로 해석) = EPDof(StormBase) 가 되어야 chain 이 MapHandleSlot 에 도달.
    constexpr uint32_t kGetMapHandleProbe = 0x4FE304u;
    // EPD page 가 정렬에 따라 다른 영역과 겹칠 수 있어 신중히. 0x4FE000..0x4FF000 (4KB) 잡고 그 안에 두 주소.
    if (!mem_.findBlock(kGetMapHandleProbe)) {
        constexpr uint32_t kProbePage = kGetMapHandleProbe & ~0xFFFu;  // 0x4FE000
        constexpr uint32_t kProbeSize = 0x2000u;                       // 8KB covers up to 0x4FFFFF
        try { mem_.allocAt(kProbePage, kProbeSize, "GetMapHandleProbe"); }
        catch (...) { /* 이미 다른 alloc 과 겹치면 패스 — 그래도 write 는 시도 */ }
    }
    mem_.writeU32(kGetMapHandleProbe, EPDof(sc::StormBaseExpected));

    // 2) MapHandleSlot at 0x1505ADFC — RAW pointer (옛 코드 그대로).
    mem_.writeU32(sc::StormMapHandleSlot, kStormBaseAddr);

    // 3) MapHandle struct fields — RAW addresses. 옛 코드 그대로.
    mem_.allocAt(kMapHandleAddr, 0x200, "MapHandle");
    mem_.writeU32(kMapHandleAddr + 0x130, kMpqHeaderAddr);  // RAW: mpqHeader (= mpqDataAddr)
    mem_.writeU32(kMapHandleAddr + 0x134, kBlockTableAddr); // RAW: block table
    mem_.writeU32(kMapHandleAddr + 0x138, kHashTableAddr);  // RAW: hash table

    // 4) MPQ header 32바이트 — raw 그대로 (옛 코드는 +0x18/+0x1C 안 덮어씀, header 자체에 valid 값).
    mem_.allocAt(kMpqHeaderAddr, 0x20, "MpqHeader");
    if (mpqHeader32) {
        mem_.writeBytes(kMpqHeaderAddr, mpqHeader32, 32);
    }

    // 5) Decrypted hash table — 1024 × 16 bytes = 16KB 일반적
    uint32_t hashBytes = static_cast<uint32_t>(decryptedHashTable.size() * sizeof(HashTableEntry));
    mem_.allocAt(kHashTableAddr, hashBytes, "MpqHashTable");
    mem_.writeBytes(kHashTableAddr,
                    reinterpret_cast<const uint8_t*>(decryptedHashTable.data()),
                    hashBytes);

    // 6) Decrypted block table — 큰 사이즈
    uint32_t blockBytes = static_cast<uint32_t>(decryptedBlockTable.size() * sizeof(BlockTableEntry));
    mem_.allocAt(kBlockTableAddr, blockBytes, "MpqBlockTable");
    mem_.writeBytes(kBlockTableAddr,
                    reinterpret_cast<const uint8_t*>(decryptedBlockTable.data()),
                    blockBytes);

    // 7) Raw MPQ bytes (keycalc 의 sector table feed 용)
    if (!rawMpqBytes.empty()) {
        mem_.allocAt(kRawMpqAddr,
                     static_cast<uint32_t>(rawMpqBytes.size()), "MpqRawFile");
        mem_.writeBytes(kRawMpqAddr, rawMpqBytes.data(),
                        static_cast<uint32_t>(rawMpqBytes.size()));
    }

    if (g_melterVerbose) std::fprintf(stderr, "[mockStormMpq] MapHandle=0x%08X  MPQHeader=0x%08X  "
                          "HashTable=0x%08X(%u)  BlockTable=0x%08X(%u)\n",
                 kMapHandleAddr, kMpqHeaderAddr,
                 kHashTableAddr, hashBytes,
                 kBlockTableAddr, blockBytes);
    if (g_melterVerbose) std::fprintf(stderr, "[mockStormMpq] addrs: MapHandle=0x%08X mpqHdrField=0x%08X "
                          "blockTbl=0x%08X hashTbl=0x%08X\n",
                 kMapHandleAddr, kMpqHeaderAddr + 0x18, kBlockTableAddr, kHashTableAddr);
    if (g_melterVerbose) std::fprintf(stderr, "[mockStormMpq] SStrLen@0x4FE544=0x%08X (expect=0x%08X)  "
                          "StormMapHandleSlot@0x1505ADFC=0x%08X (expect=0x%08X)\n",
                 mem_.readU32(sc::StormSStrLenImport),
                 sc::StormBaseExpected,
                 mem_.readU32(sc::StormMapHandleSlot),
                 kMapHandleAddr);
}

// 옛 코드의 VMemoryAlloc{STRx,MRGN,PTEx,PUPx}Section 정확히 따라하기.
void TrigEmulator::loadChkSectionData(const std::vector<uint8_t>& chk) {
    // STRx section → 0x191943C8 (= sc::StrxSectionAlloc) — 옛 코드 정확:
    // staticAllocVMemoryBlock(STRx_ALLOC_ADDRESS, STRxSection.size);  // 전체 size alloc
    // writeMemory(STRx_ALLOC_ADDRESS, STRxSection.data, ...);          // 전체 data write
    // payload 는 STRx 안의 일부 (= eudplib code). STRx alloc 가 payload 도 cover.
    {
        size_t strxSize = 0;
        size_t strxOff = findSectionOffset(chk, "STRx", strxSize);
        if (strxOff != (size_t)-1 && strxSize > 0) {
            uint32_t writeSize = (uint32_t)strxSize;
            // 이미 다른 alloc (= payload 등) 가 있으면 그 영역 제거 후 STRx 전체 alloc
            mem_.deallocRange(sc::StrxSectionAlloc, writeSize);
            mem_.allocAt(sc::StrxSectionAlloc, writeSize, "STRx");
            mem_.writeBytes(sc::StrxSectionAlloc, chk.data() + strxOff, writeSize);
            if (g_melterVerbose) std::fprintf(stderr, "[chkData] STRx %u bytes → 0x%08X\n",
                         writeSize, sc::StrxSectionAlloc);
        }
    }

    // MRGN section → 0x58DC60 (= sc::MRGNTable)
    {
        size_t mrgnSize = 0;
        size_t mrgnOff = findSectionOffset(chk, "MRGN", mrgnSize);
        if (mrgnOff != (size_t)-1 && mrgnSize > 0) {
            uint32_t writeSize = (uint32_t)std::min<size_t>(mrgnSize, 5100);
            try {
                mem_.writeBytes(sc::MRGNTable, chk.data() + mrgnOff, writeSize);
                if (g_melterVerbose) std::fprintf(stderr, "[chkData] MRGN %u bytes → 0x%08X\n",
                             writeSize, sc::MRGNTable);
            } catch (...) {}
        }
    }
    // PTEx section: bytes[24..43+44*p] → 0x58F050 + 20*p (BW Tech Available),
    //              bytes[24+44*12..43+44*12+44*p] → 0x58F140 + 20*p (BW Tech Researched)
    {
        size_t ptexSize = 0;
        size_t ptexOff = findSectionOffset(chk, "PTEx", ptexSize);
        if (ptexOff != (size_t)-1 && ptexSize > 0) {
            int hits = 0;
            for (uint8_t p = 0; p < 12; ++p) {
                for (uint8_t i = 0; i < 20; ++i) {
                    size_t srcOff1 = i + 24 + 44 * p;
                    size_t srcOff2 = i + 24 + 44 * p + 44 * 12;
                    if (srcOff1 < ptexSize) {
                        try {
                            mem_.writeU8(sc::BwTechAvailable + i + 20 * p,
                                         chk[ptexOff + srcOff1]);
                            hits++;
                        } catch (...) {}
                    }
                    if (srcOff2 < ptexSize) {
                        try {
                            mem_.writeU8(sc::BwTechResearched + i + 20 * p,
                                         chk[ptexOff + srcOff2]);
                            hits++;
                        } catch (...) {}
                    }
                }
            }
            if (g_melterVerbose) std::fprintf(stderr, "[chkData] PTEx %d bytes written\n", hits);
        }
    }
    // PUPx section layout: PlayerMaximumUpgradeLevel[12][61] @0, PlayerStartingUpgradeLevel[12][61] @732.
    // SC loads BW upgrades (u=46..60) into the runtime BW tables:
    //   BwUpgradesAvailable (0x58F278) <- PlayerMaximumUpgradeLevel[p][46+i]
    //   BwUpgradesResearched (0x58F32C) <- PlayerStartingUpgradeLevel[p][46+i]
    // These two tables are contiguous (180+180=360B) and freeze's RestorePUPx copies the
    // raw 360 bytes (90 dwords, Available region first) into obfuData, which getObf reads as
    // obf_pupx = oBFmaxBW + oBFstartBW (max region first). So Available MUST map from PlayerMax,
    // NOT PlayerStart — getting this backwards corrupts obfuData and breaks the whole keycalc
    // bootstrap (stormRelocateAmount). Verified: Max→Available yields the correct EPD chain.
    {
        size_t pupxSize = 0;
        size_t pupxOff = findSectionOffset(chk, "PUPx", pupxSize);
        if (pupxOff != (size_t)-1 && pupxSize > 0) {
            int hits = 0;
            for (uint8_t p = 0; p < 12; ++p) {
                for (uint8_t i = 0; i < 15; ++i) {
                    size_t srcMax   = i + 46 + 61 * p;            // PlayerMaximumUpgradeLevel
                    size_t srcStart = i + 46 + 61 * p + 61 * 12;  // PlayerStartingUpgradeLevel
                    if (srcMax < pupxSize) {
                        try {
                            mem_.writeU8(sc::BwUpgradesAvailable + i + 15 * p,
                                         chk[pupxOff + srcMax]);
                            hits++;
                        } catch (...) {}
                    }
                    if (srcStart < pupxSize) {
                        try {
                            mem_.writeU8(sc::BwUpgradesResearched + i + 15 * p,
                                         chk[pupxOff + srcStart]);
                            hits++;
                        } catch (...) {}
                    }
                }
            }
            if (g_melterVerbose) std::fprintf(stderr, "[chkData] PUPx %d bytes written\n", hits);
        }
    }

    // ───── 추가 chk section → SC 메모리 매핑 (옛 코드 안 한 것들) ─────
    // 사용자 요청: 가져올 수 있는 데이터 다 가져오기 (같은 로직).

    auto loadInto = [&](const char* sec, uint32_t dstAddr, size_t maxSize, const char* label) {
        size_t size = 0;
        size_t off = findSectionOffset(chk, sec, size);
        if (off == (size_t)-1 || size == 0) return;
        size_t n = std::min(size, maxSize);
        try {
            mem_.writeBytes(dstAddr, chk.data() + off, (uint32_t)n);
            if (g_melterVerbose) std::fprintf(stderr, "[chkData] %s %zu bytes → 0x%08X (%s)\n",
                         sec, n, dstAddr, label);
        } catch (...) {}
    };

    // DIM (4 byte) → 0x0057F1D4 MapSize
    loadInto("DIM ", 0x0057F1D4, 4, "MapSize");
    // OWNR (12 byte) → 0x0057F1B4 Player Slot Types
    loadInto("OWNR", 0x0057F1B4, 12, "PlayerSlotTypes");
    // SIDE (12 byte) → 0x0057F1C0 Player Slot Races
    loadInto("SIDE", 0x0057F1C0, 12, "PlayerSlotRaces");
    // COLR (8 byte) → 0x0057F21C Player Color Mapping
    loadInto("COLR", 0x0057F21C, 8, "PlayerColorMapping");
    // ERA (2 byte) → 0x0057F1DC Tileset
    loadInto("ERA ", 0x0057F1DC, 2, "Tileset");
    // FORC (20 byte) → 0x0058D5B0 Player's Force + Force Names
    loadInto("FORC", 0x0058D5B0, 20, "ForceInfo");

    // SWNM (256*4 = 1024 byte) → ?? — switch names string indices
    // (SC mem 정확한 위치 없음. 직접 사용 시 SetSwitch 액션의 결과 영향)

    // UNIS (228 unit settings, 4168 byte) → 0x005C106C Units.dat 영역 일부 override
    //   진짜 SC 는 .dat file 로 load 한 후 UNIS 가 override. 우리는 .dat 가 0 init 이므로
    //   UNIS 값으로 채우면 SC 와 유사.
    {
        size_t sz = 0;
        size_t off = findSectionOffset(chk, "UNIS", sz);
        if (off != (size_t)-1 && sz > 0) {
            // UNIS format: 228 unit × 19 byte = 4332 byte
            //   bytes[0..227] = uses_default[u]
            //   bytes[228..683] = hp[u] × 4
            //   bytes[684..1139] = shield[u] × 2
            //   ... 등 복잡, 단순 dump 우선
            size_t n = std::min(sz, (size_t)4332);
            try {
                // 임시: UNIS 데이터를 0x00514000 (Unit Reqs 직전) 부근에 dump
                // 정확한 SC layout 매핑은 복잡. 일단 raw inject.
                mem_.writeBytes(0x00514000, chk.data() + off, (uint32_t)n);
                if (g_melterVerbose) std::fprintf(stderr, "[chkData] UNIS %zu bytes → 0x00514000 (raw)\n", n);
            } catch (...) {}
        }
    }
    // UPGS (598 byte) → ??
    // TECS (216 byte) → ??

    // SPRP (4 byte) → 0x0057F244 Campaign Index? (실제 SC 의 SPRP 처리 다름)
    //   SPRP = scenario name index + scenario description index (each 2 byte)
    loadInto("SPRP", 0x0057F244, 4, "ScenarioName_Desc_idx");

    // PUNI (228 + 12*228 = 2964 byte) — player unit availability
    //   진짜 SC: 0x57F27C "Player Units available" 228 byte
    //   PUNI 의 첫 228 byte = global availability, 그 후 12*228 = per-player override
    loadInto("PUNI", 0x0057F27C, 228, "PlayerUnitsAvailable");

    // UPGR (28 byte) — global upgrade levels
    //   진짜 SC mem 위치 모름 — skip
    // PTEC (216 byte) — global tech availability
    //   skip

    // VER (2 byte) → 0x0057F1DC ?? — 사실 ERA 와 같은 자리. VER 가 더 우선이면 덮어씌움.
    // → skip, ERA 이미 매핑됨

    // MTXM (very large, map tile data) → 0x005993C8 (MTXM pointer) → 별도 buffer alloc
    {
        size_t sz = 0;
        size_t off = findSectionOffset(chk, "MTXM", sz);
        if (off != (size_t)-1 && sz > 0) {
            // MTXM 의 진짜 SC mem: 동적 alloc, MtxmPointer (0x5993C4) 가 가리킴
            // 임시 alloc 한 영역 (0x4000000) 에 MTXM 매핑, MtxmPointer 도 갱신
            constexpr uint32_t kMtxmAddr = 0x04000000;
            try {
                mem_.allocAt(kMtxmAddr, (uint32_t)sz, "MTXM-data");
                mem_.writeBytes(kMtxmAddr, chk.data() + off, (uint32_t)sz);
                mem_.writeU32(sc::MtxmPointer, kMtxmAddr);
                if (g_melterVerbose) std::fprintf(stderr, "[chkData] MTXM %zu bytes → 0x%08X (ptr in 0x5993C4)\n",
                             sz, kMtxmAddr);
            } catch (...) {}
        }
    }
}

void TrigEmulator::loadMpqIntoStorm(const std::vector<uint8_t>& mpqBytes,
                                     uint32_t stormOffset) {
    // Storm region 안 stormOffset 위치에 MPQ 파일 raw bytes 매핑.
    // MapHandle 슬롯이 이 영역을 가리키도록 갱신.
    uint32_t base = sc::StormBaseExpected + stormOffset;
    uint32_t size = static_cast<uint32_t>(mpqBytes.size());

    // Storm region 안에 들어가야 함. 작은 모킹 (64KB) 보다 크면 별도 alloc.
    auto* blk = mem_.findBlock(base);
    if (!blk) {
        // Storm region 안이 아니면 별도로 할당
        mem_.allocAt(base, size, "MpqData");
    } else {
        // 이미 매핑된 영역에 덮어쓰기 (Storm region 안)
    }
    mem_.writeBytes(base, mpqBytes);
    mem_.writeU32(sc::StormMapHandleSlot, base);
    std::fprintf(stderr, "[mpq] loaded %u bytes at 0x%08X, MapHandle←0x%08X\n",
                 size, base, base);
}

void TrigEmulator::loadTrigSection(const std::vector<uint8_t>& trigSection) {
    // freeze 의 keycalc 는 in-memory TRIG 를 직접 읽지 않음 — Storm MPQ 핸들을 읽음.
    // 우리는 트리거 실행 자체만 시뮬레이트하므로 TRIG 데이터 영역을 가상주소에 매핑만.
    mem_.allocAt(sc::TrigSectionAlloc, static_cast<uint32_t>(trigSection.size()), "TRIG");
    mem_.writeBytes(sc::TrigSectionAlloc, trigSection);
}

// preserveTriggerFlag_: executeTrigger 안 actions 중 PreserveTrigger (acttype=3) 검출 여부.
// executeTriggerAt 에서 그것 기반으로 trigger 의 flag 0x8 set/skip 결정.
void TrigEmulator::executeTrigger(const EmTrigger& trig, uint32_t baseAddr) {
    triggersExecuted_++;
    preserveTriggerFlag_ = false;

    // 조건 평가: 옛 SC 동작 — condtype==0 만나면 break (NOT continue)
    //   condition.flag & 0x2 (disabled) 는 skip
    int condsMet = 0;
    for (int i = 0; i < 16; ++i) {
        EmCondition c = trig.conditions[i];
        if (baseAddr) {
            // SC 처럼 실행 직전 메모리에서 재독 (self-modify 반영)
            uint32_t ca = baseAddr + uint32_t(i) * 20;
            try {
                c.locID = mem_.readU32(ca + 0);   c.player = mem_.readU32(ca + 4);
                c.amount = mem_.readU32(ca + 8);  c.unitID = mem_.readU16(ca + 12);
                c.comparison = mem_.readU8(ca + 14); c.condtype = mem_.readU8(ca + 15);
                c.restype = mem_.readU8(ca + 16); c.flag = mem_.readU8(ca + 17);
                c.eudx = mem_.readU16(ca + 18);
            } catch (...) {}
        }
        if (c.flag & 0x2) continue;        // FIX: disabled condition → skip
        if (c.condtype == 0) break;         // FIX: empty cond → 나머지 안 봄 (NOT continue)
        // FIX: invalid condtype (> 23) → false. enc trigger 의 garbage cond 가 우리
        //   cond_Empty(true) fallback 으로 trigger fire = wrong corruption. SC engine 의
        //   진짜 behavior 는 unknown 이나 conservative false 가 더 안전 (trigger 안 fire).
        if (c.condtype >= 24) {
            if (logTrigExec_ && !trigExecLog_.empty()) {
                trigExecLog_.back().conditionsMet = condsMet;
            }
            return;
        }
        uint8_t ct = c.condtype;
        ConditionHandler h = condTable_[ct];
        if (!(this->*h)(c)) {
            if (verbose_) std::cerr << "  cond[" << i << "] (type " << int(ct) << ") FAIL → trigger skipped\n";
            if (logTrigExec_ && !trigExecLog_.empty()) {
                trigExecLog_.back().conditionsMet = condsMet;
            }
            return;
        }
        condsMet++;
    }
    if (logTrigExec_ && !trigExecLog_.empty()) {
        trigExecLog_.back().conditionsMet = condsMet;
    }

    // 액션 실행: 옛 SC 동작 — acttype==0 만나면 break
    //   action.flags & 0x2 (disabled) 는 skip
    //   PreserveTrigger (acttype=3) 감지 → preserveTriggerFlag_ set
    uint64_t actionsInThisTrigger = 0;
    for (int i = 0; i < 64; ++i) {
        EmAction a = trig.actions[i];
        if (baseAddr) {
            // SC 처럼 실행 직전 메모리에서 재독 — 한 트리거 안의 앞 액션이 이 액션의
            // dest/value/modifier/acttype 필드를 self-modify 했으면 반영.
            uint32_t aa = baseAddr + 320u + uint32_t(i) * 32u;
            uint8_t at0 = a.acttype;
            try { at0 = mem_.readU8(aa + 26); } catch (...) {}
            a.acttype = at0;
            if (at0 != 0) {
                try {
                    a.locID = mem_.readU32(aa + 0);  a.strID = mem_.readU32(aa + 4);
                    a.wavID = mem_.readU32(aa + 8);  a.time = mem_.readU32(aa + 12);
                    a.player1 = mem_.readU32(aa + 16); a.player2 = mem_.readU32(aa + 20);
                    a.unitID = mem_.readU16(aa + 24); a.modifier = mem_.readU8(aa + 27);
                    a.flags = mem_.readU8(aa + 28);  a.internal1 = mem_.readU8(aa + 29);
                    a.eudx = mem_.readU16(aa + 30);  a.mask = a.eudx;
                } catch (...) {}
            }
        }
        if (a.flags & 0x2) continue;        // FIX: disabled action → skip
        if (a.acttype == 0) break;          // FIX: empty act → 나머지 안 봄
        if (++actionsInThisTrigger > actionCap_) {
            if (verbose_) std::cerr << "  action cap reached, aborting trigger\n";
            break;
        }
        if (a.acttype == 3) {               // FIX: PreserveTrigger detected
            preserveTriggerFlag_ = true;
        }
        uint8_t at = a.acttype < 64 ? a.acttype : 0;
        actionsExecuted_++;
        ActionHandler h = actTable_[at];
        (this->*h)(a);
    }
    if (logTrigExec_ && !trigExecLog_.empty()) {
        trigExecLog_.back().actionsRun = (int)actionsInThisTrigger;
    }
}

void TrigEmulator::executeTriggerAt(uint32_t address) {
    // Global stop
    if (globalTriggerLimit_ != 0 && trigExecLog_.size() >= globalTriggerLimit_) return;
    if (logTrigExec_) {
        TrigExecEvent ev{};
        ev.seq        = (uint64_t)trigExecLog_.size();
        ev.addr       = address;
        try { ev.flagBefore = mem_.readU32(address + 2368); } catch (...) { ev.flagBefore = 0; }
        ev.setMemBegin = setMemoryLog_.size();
        ev.readBegin   = readLog_.size();
        trigExecLog_.push_back(ev);
    }
    std::vector<uint8_t> bytes = mem_.readBytes(address, 2400);
    uint32_t flag = 0;
    if (bytes.size() >= 2372) std::memcpy(&flag, bytes.data() + 2368, 4);
    // FIX 1 — REMOVED: encrypted skip (SC engine doesn't check this bit).
    //   SC 는 ENCRYPTED 인지 모르고 garbage cond/act 그냥 평가. 우리도 같게.
    //   invalid opcode 만나면 우리 ct%24=0 (cond_Empty=true) fallback — SC garbage call 과 거의 동등.
    // FIX 2: SC trigger disabled flag (= flag & 0x8) — trigger 이미 실행됨 → skip
    if (autoDisableBit_ && (flag & 0x8u)) {
        if (logTrigExec_ && !trigExecLog_.empty()) {
            trigExecLog_.back().conditionsMet = 0;
            trigExecLog_.back().actionsRun = 0;
        }
        if (logTrigExec_) {
            auto& ev = trigExecLog_.back();
            ev.setMemEnd = setMemoryLog_.size();
            ev.readEnd   = readLog_.size();
        }
        return;
    }
    EmTrigger trig;
    parseEmTrigger(bytes.data(), trig);
    executeTrigger(trig, address);  // address 전달 → 각 액션 실행 직전 메모리 재독 (self-modify 반영)
    // 실제 SC engine 동작 (검색 결과로 검증):
    //   non-preserve trigger 는 fire 후 0x8 (Disabled) bit set → 같은 chain pass 의
    //   subsequent visit 에서 skip → chain 한 frame 안에 자연 종료.
    //   ※ 옛 emulator (old_ref3) 는 by-value 라서 실제 mem 안 set = 그것은 SC 와 다른 buggy 동작.
    bool isPreserved = preserveTriggerFlag_ || (flag & 0x4u);
    if (autoDisableBit_ && !isPreserved) {
        try { mem_.writeU32(address + 2368, flag | 0x8u); } catch (...) {}
    }
    if (logTrigExec_) {
        auto& ev = trigExecLog_.back();
        ev.setMemEnd = setMemoryLog_.size();
        ev.readEnd   = readLog_.size();
    }
}

// ─────────── 조건/액션 헬퍼 ───────────
bool TrigEmulator::compareValues(uint32_t left, uint8_t comparison, uint32_t right) const {
    // SC trigger comparison values:
    //   0 = AtLeast (left >= right)
    //   1 = AtMost  (left <= right)
    //   10 = Exactly (left == right)
    switch (comparison) {
        case 0:  return left >= right;
        case 1:  return left <= right;
        case 10: return left == right;
        default: return false;
    }
}

uint32_t TrigEmulator::applyModifier(uint32_t current, uint8_t modifier, uint32_t value) const {
    // SC SetDeaths modifier:
    //   7 = SetTo
    //   8 = Add
    //   9 = Subtract
    switch (modifier) {
        case 7: return value;
        case 8: return current + value;        // uint overflow 자동
        case 9: return (current > value) ? (current - value) : 0;  // SC saturation at 0
        default: return current;
    }
}

// ─────────── condtype 15 = Deaths / DeathsX / Memory ───────────
// SC 의 EUD trick:
//   - player 0..11 + unitID 0..227: 일반 SetDeaths 슬롯 검사
//   - player > 11 (특히 large): EPD 인코딩 → 임의 메모리 위치 검사 (= Memory() condition)
// EUDx == 0x4353 이면 DeathsX (마스크 적용).
// 옛 코드 readMemory hook addresses — 의미 있는 access detection
static void debugMemAccess(uint32_t addr) {
    if (!g_melterVerbose) return;
    if (addr == 0x16000138) std::fprintf(stderr, "[hook] log toggle @ 0x16000138\n");
    if (addr == 0x57F23C)   std::fprintf(stderr, "[hook] Game Tick Reached @ 0x57F23C\n");
    if (addr == 0x641598)   std::fprintf(stderr, "[hook] eprintln @ 0x641598\n");
}

bool TrigEmulator::cond_Deaths(const EmCondition& c) {
    memCondChecks_++;
    uint32_t player = c.player;
    bool isCp = (player == 13);
    if (isCp) {
        try { player = mem_.readU32(sc::CurrentPlayer); } catch (...) {}
    }
    // EUD trick 은 player > 11 (garbage addr) 도 valid 라 가정. SC engine 의 cond_Deaths 가
    // range check 없이 raw addr read 함 = 우리 동작. range check 추가하면 EUD 깨짐.
    // 다만 EUDx (mask) 가 없고 player > 11 면 vanilla cond_Deaths 가 invalid → false 가능성.
    // 시도: eudx == 0 (= vanilla Deaths, NOT SetDeathsX) 이고 player > 11 이면 false.
    // FIX (narrow): vanilla Deaths + player>11 + addr UNMAPPED → false.
    //   BWAPI 따르면 PlayerGroups 0~26 valid. 그러나 우리 emulator 의 다른 부정확 source 때문에
    //   player>26 으로 narrow 하면 false positive 3개 다시 등장 (trig 356 진짜 valid 도 사라짐).
    //   현실적 trade-off: player>11 이 lucky 하게 1 진짜 valid 잡음.
    if (c.eudx != 0x4353 && player > 11) {
        uint32_t pAddr = sc::DeathTable + uint32_t(c.unitID) * 48 + player * 4;
        if (!mem_.findBlock(pAddr)) {
            if (logReads_ && readWatched(pAddr)) {
                ReadEvent re;
                re.addr = pAddr; re.value = 0; re.mask = 0xFFFFFFFFu;
                re.comparison = c.comparison; re.amount = c.amount;
                re.conditionMet = false; re.isCpMagic = isCp;
                readLog_.push_back(re);
            }
            return false;
        }
        // else: mapped → fall through to raw read (정상 EUD trick polling)
    }
    uint32_t addr = sc::DeathTable + uint32_t(c.unitID) * 48 + player * 4;

    debugMemAccess(addr);
    uint32_t value = 0;
    auto* blk = mem_.findBlock(addr);
    if (blk) {
        value = mem_.readU32(addr);
    } else {
        unmappedReads_++;
        // 모든 unmapped read 주소들 수집 — SC 의 어떤 구조에 속하는지 분석용
        unmappedReadAddrs_[addr]++;
        if (addr >= 0x80000000u) highMemReadAddrs_[addr]++;
    }

    uint32_t mask = 0xFFFFFFFFu;
    if (c.eudx == 0x4353) {
        mask = c.locID;
        // FIX: mask=0 일 때 fallback 제거. SC engine 은 mask=0 → (value & 0) = 0 평가.
        //   우리 가 fallback 으로 0xFFFFFFFF 사용 한 게 wrong eval. 진짜 SC 대로.
    }
    bool met = compareValues(value & mask, c.comparison, c.amount);

    if (logReads_ && readWatched(addr)) {
        ReadEvent re;
        re.addr = addr;
        re.value = value;
        re.mask = mask;
        re.comparison = c.comparison;
        re.amount = c.amount;
        re.conditionMet = met;
        re.isCpMagic = isCp;
        readLog_.push_back(re);
    }

    return met;
}

// ─────────── acttype 45 = SetDeaths / SetDeathsX / SetMemory ───────────
// SC 의 EUD trick:
//   - byte16(player1) = destination "player number". EPD 변환 적용시 임의 메모리 주소
//   - byte20(player2) = value to set/add/subtract
//   - byte24(unitID)  = unit index (DeathTable 안)
//   - byte27(modifier)= 7=SetTo / 8=Add / 9=Subtract
//   - player1 == 13: CurrentPlayer magic — 실제 player 는 sc::CurrentPlayer 메모리 값
// freeze 의 assigner 는 거의 다 이 형태 (player>11 인 EPD 변형).
void TrigEmulator::act_SetDeathsLike(const EmAction& a) {
    // CurrentPlayer magic: player1 == 13 이면 sc::CurrentPlayer 값 사용
    uint32_t player = a.player1;
    if (player == 13) {
        try { player = mem_.readU32(sc::CurrentPlayer); } catch (...) {}
    }

    // SetMemory 로그 — VMemory 매핑이 안 맞아도 의도된 쓰기 기록.
    // FIX: ev.player1 = resolved (CP magic 적용 후). 분석 도구 의 dest 계산이 raw 13 사용으로
    //   잘못된 vanilla DeathTable[0][13] 보고 했던 bug 수정. 이제 ev.player1 = real player number.
    if (logSetMemory_) {
        SetMemoryEvent ev;
        ev.player1  = player;     // RESOLVED player (CP 적용 후)
        ev.unitID   = a.unitID;
        ev.modifier = a.modifier;
        ev.value    = a.player2;
        // FIX: real write mask = a.locID for SetDeathsX (eudx==0x4353); full otherwise.
        //   (a.mask was a.eudx = the 0x4353 marker, NOT the mask — broke log-replay analysis.)
        //   mask=0 fallback 제거 (line 812 실제 write 와 일관) — mask=0 은 항등이지 full 아님.
        ev.mask     = (a.eudx == 0x4353) ? a.locID : 0xFFFFFFFFu;
        setMemoryLog_.push_back(ev);
    }

    // SC death table 레이아웃 [unit][player]: per-unit stride 48, per-player stride 4
    //   addr = 0x58A364 + unit * 48 + player * 4
    // eudplib 의 SetMemory(dest) = SetDeaths(EPD(dest), ..., unit=0) → addr = base + 0*48 + EPD*4 = dest ✓
    uint32_t addr = sc::DeathTable + uint32_t(a.unitID) * 48 + player * 4;

    auto* blk = mem_.findBlock(addr);
    if (!blk) {
        // 매핑 안 됨 — on-demand 4KB page 할당 (EUDVariable user space 대응)
        constexpr uint32_t PAGE_SIZE = 4096;
        uint32_t pageBase = addr & ~(PAGE_SIZE - 1);
        try {
            mem_.allocAt(pageBase, PAGE_SIZE, "EUD-userpage");
            if (verbose_) {
                std::cerr << "  auto-alloc page 0x" << std::hex << pageBase
                          << " for SetMemory target 0x" << addr << "\n";
            }
        } catch (const std::exception& e) {
            // 다른 페이지와 겹치면 못 할당 — 그냥 패스
            if (verbose_) std::cerr << "  alloc fail: " << e.what() << "\n";
            return;
        }
    }

    uint32_t current = mem_.readU32(addr);
    uint32_t value = a.player2;  // SetDeaths 의 값 필드
    uint32_t result;
    if (a.eudx == 0x4353) {
        // SetDeathsX: mask 는 action 의 locID (byte 0..3).
        // FIX (masked-plane modifier): SC 의 SetDeathsX 는 Add/Subtract 시 carry/borrow 가
        //   mask 밖으로 새지 않도록 *masked bit-plane 안에서만* 연산한다. 따라서 두 피연산자를
        //   먼저 mask 로 자르고 연산한 뒤 다시 & mask 로 plane 에 가둔다:
        //       plane = applyModifier(current & mask, mod, value & mask) & mask
        //       result = (current & ~mask) | plane
        //   이전 코드는 full-word (current+value) 후 & mask 라서 carry 가 plane 경계를 넘어가
        //   eudplib 의 XOR(두 masked Add: 0x55555555 / 0xAAAAAAAA), negate, shift, OR/AND 트릭이
        //   전부 깨졌다. 이게 freeze 의 bit-by-bit dword copy(f_dwread/f_dwadd)와 keycalc
        //   de-obfuscation 을 손상시켜 seedKey 가 틀리고 루프가 종료되지 않던 근본 원인이다.
        //   (SetTo 는 plane 무관하게 동일 결과; Add/Subtract 만 영향.)
        // FIX (mask=0 항등): a.locID 가 0 이면 "0 비트만 수정" = 항등(result=current).
        //   eudplib 의 |=/&= 는 SetDeathsX 의 mask 필드를 런타임에 src.value(OR) 또는 ~src(AND)
        //   로 패치한다. 그 변수가 0(OR) / 0xFFFFFFFF(AND) 이면 런타임 mask=0 이 되어야 하고
        //   실제 SC 는 dst 를 안 건드린다. 이전 fallback(? : 0xFFFFFFFF)은 mask=0 을 full-word
        //   로 오해해 dword 전체를 덮어써(OR→0xFFFFFFFF, AND→0) obfuscated assigner 의 중간
        //   0-값 변수를 오염시켰다. 조건 경로(cond_Deaths)는 이미 fallback 제거됨 — 일관되게 맞춤.
        //   아래 공식이 mask=0 을 정확히 처리: (current & ~0) | (... & 0) = current.
        uint32_t mask = a.locID;
        uint32_t modified = applyModifier(current & mask, a.modifier, value & mask);
        result = (current & ~mask) | (modified & mask);
    } else {
        result = applyModifier(current, a.modifier, value);
    }
    mem_.writeU32(addr, result);

    // MEMORY SNAPSHOT on first write to the target addr (capture intact state at this point).
    if (snapAddr_ && !snapDone_ && addr == snapAddr_) {
        try { snapshot_ = mem_.readBytes(snapStart_, snapLen_); } catch (...) {}
        snapDone_ = true;
    }

    if (!watchVals_.empty()) {
        for (uint32_t wv : watchVals_)
            if (result == wv) { watchHits_.push_back({addr, result, (uint64_t)setMemoryLog_.size()}); break; }
    }

    if (trackAddrWrites_) {
        auto& w = addrWrites_[addr];
        w.count++;
        w.lastValue = result;
    }

    if (verbose_) {
        std::cerr << "  SetDeaths/Mem: addr=0x" << std::hex << addr
                  << " mod=" << std::dec << int(a.modifier)
                  << " val=0x" << std::hex << value
                  << " → 0x" << result << "\n";
    }
}

// ─────────── Generic EUD-trick mem-write actions ───────────
// SC engine 의 act_SetCountdownTimer / SetResources / SetScore / SetSwitch 의
// 진짜 동작은 fixed base + (optional) player-indexed offset.
// EUD trick 으로 player1 이 큰 값이면 dest = base + player1 * 4 → arbitrary mem.
// 우리도 같은 logic 으로 처리 — chain stuck 의 root cause 후보.
static void scWriteWithModifier(VMemory& mem, uint32_t addr, uint8_t modifier, uint32_t value,
                                uint8_t (*applyU8)(uint8_t,uint8_t,uint32_t) = nullptr) {
    // page on-demand
    if (!mem.findBlock(addr)) {
        constexpr uint32_t PAGE_SIZE = 4096;
        uint32_t pageBase = addr & ~(PAGE_SIZE - 1);
        try { mem.allocAt(pageBase, PAGE_SIZE, "EUD-trickPage"); } catch (...) { return; }
    }
    try {
        uint32_t cur = mem.readU32(addr);
        uint32_t result;
        switch (modifier) {
            case 7: result = value; break;
            case 8: result = cur + value; break;
            case 9: result = (cur > value) ? cur - value : 0; break;
            default: return;  // invalid modifier → silent (= SC engine 의 switch default)
        }
        mem.writeU32(addr, result);
    } catch (...) {}
}

// act 13 SetSwitch — switch table @ 0x58DC40 (256 bytes, 1 byte per switch).
//   chk encoding: switch number = byte 27 (modifier slot??) — confused with eudplib.
//   가설: eudplib SetSwitch(s, mod) → chk encoding 의 p2 (byte 20) 에 switch num.
//   modifier: 4=Set, 5=Clear, 6=Toggle, 11=Randomize.
//   EUD trick: dest = base + switch_num (byte access). 256 byte 안.
void TrigEmulator::act_SetSwitch(const EmAction& a) {
    constexpr uint32_t kSwitchBase = 0x58DC40;
    uint32_t swnum = a.player2 & 0xFF;
    uint32_t addr = kSwitchBase + swnum;
    if (logSetMemory_) {
        SetMemoryEvent ev;
        ev.player1 = a.player1; ev.unitID = 0;
        ev.modifier = a.modifier; ev.value = 0;
        ev.mask = 0xFFFFFFFFu;
        setMemoryLog_.push_back(ev);
    }
    if (!mem_.findBlock(addr)) {
        uint32_t pageBase = addr & ~0xFFFu;
        try { mem_.allocAt(pageBase, 0x1000, "EUD-SwPage"); } catch (...) { return; }
    }
    try {
        uint8_t cur = mem_.readU8(addr);
        uint8_t result = cur;
        switch (a.modifier) {
            case 4: result = 1; break;
            case 5: result = 0; break;
            case 6: result = cur ^ 1; break;
            default: return;
        }
        mem_.writeU8(addr, result);
    } catch (...) {}
}

// act 14 SetCountdownTimer — fixed @ 0x58D6F8 (4 bytes, single global).
//   EUD trick: dest = 0x58D6F8 + p1*4 → arbitrary mem (single-player-style extension).
//   value = time field (12..15).
void TrigEmulator::act_SetCountdownTimer(const EmAction& a) {
    // SC 1.16.1 Countdown Timer = 0x58D6F4 (verified: eud-book entry, single global dword).
    // (Was 0x58D6F8 — off by 4.) Value is in the `time` field (offset 12) per eudplib
    // SetCountdownTimer = Action(0,0,0,time,0,0,0,14,modifier,4).
    constexpr uint32_t kCountdownBase = 0x58D6F4;
    uint32_t player = a.player1;
    if (player == 13) {
        try { player = mem_.readU32(sc::CurrentPlayer); } catch (...) {}
    }
    uint32_t addr = kCountdownBase + player * 4;
    if (logSetMemory_) {
        SetMemoryEvent ev;
        ev.player1 = a.player1; ev.unitID = 0;
        ev.modifier = a.modifier; ev.value = a.time;
        ev.mask = 0xFFFFFFFFu;
        setMemoryLog_.push_back(ev);
    }
    scWriteWithModifier(mem_, addr, a.modifier, a.time);
}

// act 26 SetResources — Minerals/Gas/TotalMinerals/TotalGas[8] arrays.
//   type = a.unitID (low byte): 0=Ore, 1=Gas, 2=TotalOre, 3=TotalGas.
//   player = a.player1 (EUD trick: > 11 → arbitrary mem).
//   value = a.time.
void TrigEmulator::act_SetResources(const EmAction& a) {
    // eudplib SetResources = Action(0,0,0,0, player, amount, resource_type, 26, modifier, 4):
    //   resource_type in unitID, amount(value) in `number` = player2 (offset 20).
    //   Bases (verified eudplib scdata/player.py): mineral 0x57F0F0, gas 0x57F120,
    //   cumulativeGas 0x57F150, cumulativeMineral 0x57F180. (Resource enum 0=Ore,1=Gas,2=OreAndGas.)
    static const uint32_t kResBase[] = {
        0x57F0F0, 0x57F120, 0x57F150, 0x57F180,
    };
    uint32_t type = a.unitID & 0xFF;
    if (type > 3) return;
    uint32_t player = a.player1;
    if (player == 13) {
        try { player = mem_.readU32(sc::CurrentPlayer); } catch (...) {}
    }
    uint32_t addr = kResBase[type] + player * 4;
    uint32_t value = a.player2;  // amount = `number` field (offset 20), NOT time (offset 12)
    if (logSetMemory_) {
        SetMemoryEvent ev;
        ev.player1 = a.player1; ev.unitID = a.unitID;
        ev.modifier = a.modifier; ev.value = value;
        ev.mask = 0xFFFFFFFFu;
        setMemoryLog_.push_back(ev);
    }
    scWriteWithModifier(mem_, addr, a.modifier, value);
}

// act 27 SetScore — score arrays.
//   type = a.unitID (low 3 bits): 0=Units, 1=Buildings, 2=U+B, 3=Kills, 4=Razings, 5=K+R, 6=Custom.
//   player = a.player1.
//   value = a.time.
//   기본 SC mem 주소: 0x58A1A8 + type*0x20 + player*4 (가설, 정확치 미상)
void TrigEmulator::act_SetScore(const EmAction& a) {
    // eudplib SetScore = Action(0,0,0,0, player, amount, score_type, 27, modifier, 4):
    //   score_type in unitID, amount(value) in `number` = player2 (offset 20).
    // SC score-type enum: 0=Total,1=Units,2=Buildings,3=UnitsAndBuildings,
    //   4=Kills,5=Razings,6=KillsAndRazings,7=Custom (eudplib constenc.py:216-221).
    // Per-player dword arrays (verified eudplib scdata/player.py:47-53). The combo/Total
    // types have no single settable array (engine derives sums); mapped to the nearest base
    // as a best effort — EUD-trick maps almost always use Units(1) or Custom(7).
    // NOTE: old code used 0x58A1A8 + type*0x20 which is WRONG (arrays are non-contiguous).
    static const uint32_t kScoreBase[8] = {
        0x581E44, // 0 Total      (no single array -> Units base)
        0x581E44, // 1 Units      = unitScore
        0x582024, // 2 Buildings  = buildingScore
        0x581E44, // 3 U+B        (combo -> Units base)
        0x581F04, // 4 Kills      = killScore
        0x582054, // 5 Razings    = razingScore
        0x581F04, // 6 K+R        (combo -> Kills base)
        0x5822F4, // 7 Custom     = customScore
    };
    uint32_t type = a.unitID & 0x7;
    uint32_t player = a.player1;
    if (player == 13) {
        try { player = mem_.readU32(sc::CurrentPlayer); } catch (...) {}
    }
    uint32_t addr = kScoreBase[type] + player * 4;
    uint32_t value = a.player2;  // amount = `number` field (offset 20), NOT time (offset 12)
    if (logSetMemory_) {
        SetMemoryEvent ev;
        ev.player1 = a.player1; ev.unitID = a.unitID;
        ev.modifier = a.modifier; ev.value = value;
        ev.mask = 0xFFFFFFFFu;
        setMemoryLog_.push_back(ev);
    }
    scWriteWithModifier(mem_, addr, a.modifier, value);
}

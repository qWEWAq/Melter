#ifndef MELTER_TRIG_EMULATE_H
#define MELTER_TRIG_EMULATE_H

// 트리거 에뮬레이터 — VMemory + dispatch table 기반.
//
// 원본 mpqtrig 의 trigEmulate 가 if-else 체인 + per-byte hashmap 이라 느렸음.
// 여기서는:
//   - 메모리: VMemory (std::map 정렬 트리, O(log N) 조회)
//   - dispatch: function pointer 배열 (action type 별 핸들러)
//   - 조용히 실행 (디버그 출력 옵션화)
//
// freeze 해독에 필요한 액션:
//   - 45 SetDeaths / SetDeathsX / SetMemory (모두 acttype=45, 마스크/EUDx 로 구분)
//   - 1 Victory, 2 Defeat, ..., 일반 액션들 (대부분 freeze 무관이므로 stub OK)
// 조건:
//   - 15 Deaths / DeathsX (acttype=15)
//   - Always (1), Never (2), Bring (..), Switch (..) 등 (freeze 무관 stub)

#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "mpqtypes.h"
#include "vmemory.h"

// 트리거 안의 한 액션 (32바이트).
struct EmAction {
    uint32_t locID;
    uint32_t strID;
    uint32_t wavID;
    uint32_t time;
    uint32_t player1;
    uint32_t player2;
    uint16_t unitID;
    uint8_t  acttype;
    uint8_t  modifier;
    uint8_t  flags;
    uint8_t  internal1;
    uint16_t eudx;
    uint16_t mask;       // EUDx 가 set 일때 의미 있음 (실제로는 EUDx 필드와 같은 자리이지만 ScmDraft 관습)
};

// 트리거 안의 한 조건 (20바이트).
struct EmCondition {
    uint32_t locID;
    uint32_t player;
    uint32_t amount;
    uint16_t unitID;
    uint8_t  comparison;
    uint8_t  condtype;
    uint8_t  restype;
    uint8_t  flag;
    uint16_t eudx;
};

// 2400바이트 트리거 한 개를 파싱한 결과.
struct EmTrigger {
    EmCondition conditions[16];
    EmAction actions[64];
    uint32_t flag;       // offset 2368 (encryption flag, execution count, etc.)
    uint8_t  effPlayer[28];  // offset 2372

    // 원본 바이트 (디버그/덮어쓰기용)
    const uint8_t* rawBytes = nullptr;
};

void parseEmTrigger(const uint8_t* bytes, EmTrigger& out);

// ─────────── 에뮬레이터 ───────────
class TrigEmulator {
public:
    TrigEmulator(VMemory& mem);

    // SC 의 정적 메모리 영역들을 미리 할당 (DeathTable, CurrentPlayer 등).
    // 새로 만들면 한 번만 호출.
    void initStaticAreas();

    // TRIG 섹션 바이트를 가상주소에 매핑 (sc::TrigSectionAlloc).
    void loadTrigSection(const std::vector<uint8_t>& trigSection);

    // 입력 MPQ (.scx 파일 raw bytes) 를 Storm 메모리 영역에 매핑.
    // freeze 의 keycalc 가 MPQ 데이터를 읽어서 checksum 계산하는데,
    // 이게 없으면 키 산출이 안 됨.
    void loadMpqIntoStorm(const std::vector<uint8_t>& mpqBytes,
                          uint32_t stormOffset = 0x100000);

    // freeze keycalc 가 사용하는 Storm MapHandle struct 를 mock.
    //   - mem[0x4FE544] = StormBase (= 0x15021A00) 으로 set
    //   - mem[0x1505ADFC] = EPD(MapHandle 주소)
    //   - MapHandle +0x130/+0x134/+0x138 = mpqHeader/blockTable/hashTable EPDs
    //   - MPQ header (32 bytes) + decrypted hash/block tables 를 VMemory 에 매핑
    // raw .scx 의 MPQ header 와 decrypted tables 를 인자로 받음.
    void mockStormMpqHandle(
        const uint8_t* mpqHeader32,
        const std::vector<HashTableEntry>& decryptedHashTable,
        const std::vector<BlockTableEntry>& decryptedBlockTable,
        const std::vector<uint8_t>& rawMpqBytes);

    // 옛 코드의 chk section data init — MRGN, PTEx, PUPx 의 실제 bytes 로 채움.
    //   chk 전체 bytes 받아서 section 들 찾고 그 안 데이터 write.
    void loadChkSectionData(const std::vector<uint8_t>& chk);

    // 한 트리거를 실행 (조건 평가 → 통과시 액션 실행).
    // baseAddr != 0 이면 각 조건/액션을 실행 직전 메모리에서 다시 읽음 (SC 동작 일치 —
    // 한 트리거 안에서 앞 액션이 뒤 액션 필드를 self-modify 하는 경우 반영).
    void executeTrigger(const EmTrigger& trig, uint32_t baseAddr = 0);

    // 가상주소 base 의 2400바이트를 트리거로 파싱해 실행.
    void executeTriggerAt(uint32_t address);

    // 디버그 출력 토글.
    void setVerbose(bool v) { verbose_ = v; }

    // 한 트리거 실행 중 최대 액션 수 (loop / 보안 cap).
    void setActionCap(uint64_t cap) { actionCap_ = cap; }

    // SetMemory 액션 로깅 활성화 — VMemory 매핑 안 맞아도 의도된 쓰기를 기록.
    // 후속 분석 (freeze_analyzer) 의 candidate 소스.
    struct SetMemoryEvent {
        uint32_t player1;   // dest EPD
        uint16_t unitID;
        uint8_t  modifier;  // 7=SetTo / 8=Add / 9=Subtract
        uint32_t value;     // value field (player2)
        uint32_t mask;      // SetDeathsX 의 mask (보통 0xFFFFFFFF)
    };
    void enableSetMemoryLog(bool on) { logSetMemory_ = on; }
    const std::vector<SetMemoryEvent>& setMemoryLog() const { return setMemoryLog_; }
    void clearSetMemoryLog() { setMemoryLog_.clear(); }

    // VALUE WATCH — flag whenever a SetDeaths write's COMPUTED RESULT equals a watched value.
    //   Uses the VM's real memory/mask/initial-value, so it is authoritative (unlike log-replay).
    struct WatchHit { uint32_t addr; uint32_t value; uint64_t seq; };
    void watchForValues(const std::vector<uint32_t>& vals) { watchVals_ = vals; watchHits_.clear(); }
    const std::vector<WatchHit>& watchHits() const { return watchHits_; }

    // MEMORY SNAPSHOT — capture a region the FIRST time a target address is written (SetDeaths).
    //   Lets a probe grab the intact state at a precise execution point (e.g. seedKey at the first
    //   seedKeyArray write) without circular reasoning. snapshot() is empty until the write fires.
    void snapshotOnWrite(uint32_t addr, uint32_t regStart, uint32_t regLen) {
        snapAddr_ = addr; snapStart_ = regStart; snapLen_ = regLen; snapDone_ = false; snapshot_.clear();
    }
    const std::vector<uint8_t>& snapshot() const { return snapshot_; }
    uint32_t snapshotRegionStart() const { return snapStart_; }
    bool snapshotTaken() const { return snapDone_; }

    // 메모리 READ 로깅 — DeathsX/Deaths condition 이 어디서 무엇을 읽는지 추적.
    // eudplib 의 f_dwread_cp 는 32개 DeathsX 로 1 dword 읽음 — 패턴 식별 핵심.
    struct ReadEvent {
        uint32_t addr;     // 실제 메모리 주소 (cp-magic 적용 후)
        uint32_t value;    // 읽은 dword
        uint32_t mask;     // DeathsX mask (0xFFFFFFFF if regular Deaths)
        uint8_t comparison;
        uint32_t amount;
        bool conditionMet;
        bool isCpMagic;    // player 필드가 13 이었나
    };
    void enableReadLog(bool on) { logReads_ = on; }
    // Log only reads whose CP-resolved address is watched (avoids OOM from logging every read).
    void watchReadAddr(uint32_t a) { watchReadAddrs_.insert(a); logReads_ = true; }
    void watchReadRegion(uint32_t lo, uint32_t hi) { watchReadLo_ = lo; watchReadHi_ = hi; logReads_ = true; }
    bool readWatched(uint32_t a) const {
        if (watchReadAddrs_.empty() && watchReadLo_ >= watchReadHi_) return true;  // no filter = all
        if (watchReadAddrs_.count(a)) return true;
        return watchReadLo_ < watchReadHi_ && a >= watchReadLo_ && a < watchReadHi_;
    }
    const std::vector<ReadEvent>& readLog() const { return readLog_; }
    void clearReadLog() { readLog_.clear(); }

    // Per-target-address write tracking — assigner identification 용.
    // 키 = 실제 메모리 address (death table EPD 변환 후), value = (writeCount, lastValueWritten)
    struct WriteStat { uint64_t count = 0; uint32_t lastValue = 0; };
    void enableAddrWriteTrack(bool on) { trackAddrWrites_ = on; }
    const std::map<uint32_t, WriteStat>& addrWrites() const { return addrWrites_; }
    void clearAddrWrites() { addrWrites_.clear(); }

    // High-mem (>= 0x80000000) read attempt 추적 (디버그용).
    // 진짜 SC 에선 이런 read 는 access violation 이라 일어나면 안 됨.
    const std::map<uint32_t, uint64_t>& highMemReadAddrs() const { return highMemReadAddrs_; }
    void clearHighMemReadAddrs() { highMemReadAddrs_.clear(); }

    // 모든 unmapped cond_Deaths read 주소 추적.
    const std::map<uint32_t, uint64_t>& unmappedReadAddrs() const { return unmappedReadAddrs_; }
    void clearUnmappedReadAddrs() { unmappedReadAddrs_.clear(); }

    // ─────────── Per-trigger execution log (decompiler 용) ───────────
    // 매 executeTriggerAt 호출마다 하나씩 push. 시퀀스 = 호출 순서.
    // setMemoryLog 와 readLog 인덱스의 [start, end) 범위로 연동.
    struct TrigExecEvent {
        uint64_t seq;             // 글로벌 trigger exec 번호 (0-based)
        uint32_t addr;            // 트리거 주소 (= 가상 주소)
        uint32_t flagBefore;      // 트리거 flag (offset 2368) — 실행 전
        int      conditionsMet;   // true 로 평가된 조건 수
        int      actionsRun;      // 실행된 액션 수 (모든 effPlayer × actions)
        size_t   setMemBegin;     // 이 트리거 시작 시 setMemoryLog_.size()
        size_t   setMemEnd;       // 끝 시 size — [begin, end) 가 이 트리거의 SetMemory
        size_t   readBegin;       // 같은 식 readLog_ 범위
        size_t   readEnd;
    };
    void enableTriggerExecLog(bool on) { logTrigExec_ = on; }
    const std::vector<TrigExecEvent>& trigExecLog() const { return trigExecLog_; }
    void clearTrigExecLog() { trigExecLog_.clear(); }

    // Global stop: executeTriggerAt 이 N 번 호출되면 이후 호출은 NOP.
    // 0 = 무제한.
    void setGlobalTriggerLimit(uint64_t limit) { globalTriggerLimit_ = limit; }
    bool reachedGlobalLimit() const {
        return globalTriggerLimit_ != 0 && trigExecLog_.size() >= globalTriggerLimit_;
    }

    VMemory& memory() { return mem_; }

    // 실행 카운터 (디버그).
    uint64_t triggersExecuted() const { return triggersExecuted_; }
    uint64_t actionsExecuted() const { return actionsExecuted_; }
    uint64_t unmappedReads() const { return unmappedReads_; }
    uint64_t memoryConditionChecks() const { return memCondChecks_; }

private:
    VMemory& mem_;
    bool verbose_ = false;
    bool logSetMemory_ = false;
    bool trackAddrWrites_ = false;
    std::map<uint32_t, WriteStat> addrWrites_;
    bool logReads_ = false;
    std::set<uint32_t> watchReadAddrs_;
    uint32_t watchReadLo_ = 0, watchReadHi_ = 0;
    std::vector<ReadEvent> readLog_;
    uint64_t triggersExecuted_ = 0;
    uint64_t actionsExecuted_ = 0;
    uint64_t unmappedReads_ = 0;
    uint64_t memCondChecks_ = 0;
    uint64_t actionCap_ = 1024;  // 한 트리거당 최대 액션 수
    std::vector<SetMemoryEvent> setMemoryLog_;
    std::vector<uint32_t> watchVals_;
    std::vector<WatchHit> watchHits_;
    uint32_t snapAddr_ = 0, snapStart_ = 0, snapLen_ = 0;
    bool snapDone_ = false;
    std::vector<uint8_t> snapshot_;
    std::map<uint32_t, uint64_t> highMemReadAddrs_;
    std::map<uint32_t, uint64_t> unmappedReadAddrs_;
    bool logTrigExec_ = false;
    std::vector<TrigExecEvent> trigExecLog_;
    uint64_t globalTriggerLimit_ = 0;

    // ─────────── dispatch ───────────
    // 핸들러 시그니처:
    //   - 조건: 평가 결과 (true = 만족) 반환
    //   - 액션: void
    using ConditionHandler = bool (TrigEmulator::*)(const EmCondition&);
    using ActionHandler    = void (TrigEmulator::*)(const EmAction&);

    ConditionHandler condTable_[24] = {};  // condtype 0..23
    ActionHandler    actTable_[64]  = {};  // acttype 0..63 (실제 0..57 사용)

    void buildDispatchTables();

    // ─────────── 조건 핸들러들 ───────────
    bool cond_Empty(const EmCondition&) { return true; }   // type 0 = no condition
    bool cond_Always(const EmCondition&) { return true; }  // type 22
    bool cond_Never(const EmCondition&)  { return false; } // type 23
    bool cond_Deaths(const EmCondition& c);                // type 15 (Memory도 같은 타입)
    // 기본적으로 "조건이 명시되어 있으나 게임 상태에 의존하는 것" 은 OPTIMISTIC TRUE 반환
    // (assigner / decryptTrigger 같은 EUD 코드는 진행해야 하므로)
    // 단, true 가 너무 permissive 라서 garbage 누적 위험.
    // 디버그용 flag 로 toggle 가능하게 함.
    bool cond_TrueByDefault(const EmCondition&) { return defaultCondTrue_; }
public:
    void setDefaultCondTrue(bool v) { defaultCondTrue_ = v; }
    // EUD payload 트리거는 nextptr 로 프레임 내 재방문되어 루프를 형성한다.
    // SC 의 0x8 "already-executed" auto-disable 을 적용하면 재방문 시 skip 되어
    // EUDInfLoop body 가 실행 안 됨 → 무한 cycle. false 로 끄면 재실행 허용.
    void setAutoDisableBit(bool v) { autoDisableBit_ = v; }
private:
    bool defaultCondTrue_ = true;
    bool autoDisableBit_ = true;
    bool preserveTriggerFlag_ = false;  // executeTrigger 안 actions 중 PreserveTrigger 검출 여부

    // ─────────── 액션 핸들러들 ───────────
    void act_Noop(const EmAction&) {}
    void act_Comment(const EmAction&) {}                   // 47
    void act_PreserveTrigger(const EmAction&) {}           // 3
    void act_SetDeathsLike(const EmAction& a);             // 45 (SetDeaths / SetDeathsX / SetMemory)
    void act_SetSwitch(const EmAction& a);                 // 13 (Set/Clear/Toggle Switch + EUD trick)
    void act_SetCountdownTimer(const EmAction& a);         // 14 (CountdownTimer + EUD trick)
    void act_SetResources(const EmAction& a);              // 26 (Resources + EUD trick)
    void act_SetScore(const EmAction& a);                  // 27 (Score + EUD trick)

    // 비교 헬퍼 (Deaths 조건의 comparison 필드용)
    bool compareValues(uint32_t left, uint8_t comparison, uint32_t right) const;
    // modifier 별 산술 (SetDeaths action 의 modifier: 0=SetTo, 1=Add, 2=Subtract)
    uint32_t applyModifier(uint32_t current, uint8_t modifier, uint32_t value) const;
};

#endif  // MELTER_TRIG_EMULATE_H

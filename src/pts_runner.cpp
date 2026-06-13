#include "pts_runner.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <map>
#include <set>

#include "debug_log.h"
#include "sc_memory_layout.h"
#include "trig_emulate.h"
#include "vmemory.h"

constexpr uint32_t kRuntimeTriggerSize = 2408;
constexpr uint32_t kPrevOffset = 0;
constexpr uint32_t kNextOffset = 4;
constexpr uint32_t kChkOffset = 8;
constexpr uint32_t kChkTrigSize = 2400;

// effPlayer 28바이트 의 의미 (SC chk):
//   [0..7]   = 각 플레이어 (0/1)
//   [17]     = all players
//   [18..21] = forces 0..3 (각 force에 속한 모든 플레이어 → 트리거 실행)
// 우리는 단순화: player 0..7 만 check, force/all 도 처리.
static bool playerExecutesTrigger(const uint8_t* effPlayer, int player) {
    if (player >= 0 && player < 8) {
        if (effPlayer[player] != 0) return true;
    }
    if (effPlayer[17] != 0) return true;       // all-players
    // force 정보 없이는 정확한 force-based 판단 불가 — 보수적으로 force 비트가 set이면 모든 player 가 실행
    for (int f = 0; f < 4; ++f) {
        if (effPlayer[18 + f] != 0) return true;
    }
    return false;
}

PtsRunResult runPtsFlow(const std::vector<uint8_t>& chkTrigPayload,
                        VMemory& mem, TrigEmulator& emu,
                        uint64_t maxTriggersPerPlayer,
                        int maxPlayers) {
    PtsRunResult res;
    int n = static_cast<int>(chkTrigPayload.size() / kChkTrigSize);
    if (n == 0) return res;

    // 1) runtime trigger memory 할당 + chk 데이터 복사
    uint32_t runtimeBase = sc::TrigSectionAlloc;
    // sc::TrigSectionAlloc 위치는 이미 chk-flat 트리거가 매핑돼 있을 수 있음 — 다른 영역에 새로 할당
    runtimeBase = 0x21000000u;  // 별도 영역
    uint32_t runtimeSize = uint32_t(n) * kRuntimeTriggerSize;
    try {
        mem.allocAt(runtimeBase, runtimeSize, "RuntimeTRIG");
    } catch (...) {
        // 이미 있으면 다른 주소
        runtimeBase = 0x22000000u;
        mem.allocAt(runtimeBase, runtimeSize, "RuntimeTRIG");
    }

    for (int i = 0; i < n; ++i) {
        uint32_t triggerAddr = runtimeBase + uint32_t(i) * kRuntimeTriggerSize;
        // chk_data 복사
        mem.writeBytes(triggerAddr + kChkOffset,
                       chkTrigPayload.data() + i * kChkTrigSize, kChkTrigSize);
    }

    // 2) PTS 구축 — 각 player 별로 트리거 chain.
    //    PTS layout (12바이트): [unknown(4)][prev_last(4)][next_first(4)]
    //    Trigger linked list: PTS.next_first → trig.next → ... → trig.next == PTS_sentinel
    //    sentinel = sc::PlayerTrigStructBase + player*12 (PTS 자체 주소)
    for (int player = 0; player < 8; ++player) {
        // 이 player 에 속하는 트리거들의 chk 인덱스 모으기
        std::vector<int> playerTrigs;
        for (int i = 0; i < n; ++i) {
            const uint8_t* eff = chkTrigPayload.data() + i * kChkTrigSize + 2372;
            if (playerExecutesTrigger(eff, player)) {
                playerTrigs.push_back(i);
            }
        }
        uint32_t ptsAddr = sc::PlayerTrigStructBase + uint32_t(player) * 12;
        if (playerTrigs.empty()) {
            mem.writeU32(ptsAddr + 4, ptsAddr);  // prev_last = self (empty)
            mem.writeU32(ptsAddr + 8, ptsAddr);  // next_first = self (empty)
            continue;
        }
        // first trigger 의 prev = PTS sentinel
        // 각 trigger 의 next = next trigger
        // last trigger 의 next = PTS sentinel
        for (size_t k = 0; k < playerTrigs.size(); ++k) {
            int i = playerTrigs[k];
            uint32_t triggerAddr = runtimeBase + uint32_t(i) * kRuntimeTriggerSize;
            uint32_t prev = (k == 0) ? ptsAddr
                                     : runtimeBase + uint32_t(playerTrigs[k - 1]) * kRuntimeTriggerSize;
            uint32_t next = (k + 1 == playerTrigs.size()) ? ptsAddr
                                                          : runtimeBase + uint32_t(playerTrigs[k + 1]) * kRuntimeTriggerSize;
            mem.writeU32(triggerAddr + kPrevOffset, prev);
            mem.writeU32(triggerAddr + kNextOffset, next);
        }
        mem.writeU32(ptsAddr + 4, runtimeBase + uint32_t(playerTrigs.back()) * kRuntimeTriggerSize);
        mem.writeU32(ptsAddr + 8, runtimeBase + uint32_t(playerTrigs.front()) * kRuntimeTriggerSize);
    }

    // SC-DYNAMIC FOOTGUN FIX: freeze's unFreeze() calls RestorePUPx() FIRST (freeze.py L50),
    // which copies PUPx/PTEx (0x58F278/0x58F050 — the obfuData hidden-data source SC loaded from
    // the map) into obfuData, then writes restore_pupx (the ORIGINAL upgrade values) BACK over
    // those tables. So the hidden data is destroyed after one run. The real game runs unFreeze
    // ONCE (the decrypt loop handles all 8 players internally); we run the chain per-player (8x),
    // so runs 2..8 would read the restored (wrong) tables -> corrupt obfuData -> wrong seedKey/
    // triggerKey/jump-deobfuscation -> derail. Snapshot the hidden tables now (PUPx 360B @0x58F278,
    // PTEx 480B @0x58F050) and restore them before EACH player's chain so every unFreeze run reads
    // the original hidden data (RestorePUPx re-derives obfuData from them each run).
    std::vector<uint8_t> pupxSnap, ptexSnap;
    try { if (mem.findBlock(sc::BwUpgradesAvailable)) pupxSnap = mem.readBytes(sc::BwUpgradesAvailable, 360); } catch (...) {}
    try { if (mem.findBlock(sc::BwTechAvailable))     ptexSnap = mem.readBytes(sc::BwTechAvailable, 480); } catch (...) {}

    // 3) 각 player 실행 (maxPlayers 만큼만 — freeze unFreeze 는 한 번만 돌아야 하므로
    //    테스트/실전에서 player 0 만 실행할 수 있게 한다. SC 의 per-player 실행을 흉내내되,
    //    EUD payload (unFreeze) 는 내부에서 8 player 를 모두 처리하므로 한 번이면 충분.)
    uint64_t totalTriggers = 0;
    for (int player = 0; player < maxPlayers; ++player) {
        // restore the obfuData hidden-data source before each unFreeze run (see footgun note above)
        if (!pupxSnap.empty()) try { mem.writeBytes(sc::BwUpgradesAvailable, pupxSnap); } catch (...) {}
        if (!ptexSnap.empty()) try { mem.writeBytes(sc::BwTechAvailable, ptexSnap); } catch (...) {}
        mem.writeU32(sc::CurrentPlayer, uint32_t(player));
        uint32_t ptsAddr = sc::PlayerTrigStructBase + uint32_t(player) * 12;
        uint32_t triggerAddr = mem.readU32(ptsAddr + 8);  // next_first

        uint64_t safetyCount = 0;
        std::set<uint32_t> visited;
        std::map<uint32_t, int> visitCount;
        const int kPerTrigVisitCap = 0;  // 0 = disabled — chain 무한 진행, cap 으로만 break
        int payloadHits = 0;
        const char* stopReason = "UNKNOWN";
        uint32_t stopAtTrigger = 0;
        while (triggerAddr != ptsAddr && safetyCount < maxTriggersPerPlayer) {
            bool inRuntime = (triggerAddr >= runtimeBase &&
                              triggerAddr < runtimeBase + runtimeSize &&
                              (triggerAddr - runtimeBase) % kRuntimeTriggerSize == 0);

            uint32_t execAddr;
            uint32_t nextAddrLoc;
            bool isVTable = false;
            if (inRuntime) {
                execAddr = triggerAddr + kChkOffset;
                nextAddrLoc = triggerAddr + kNextOffset;
            } else {
                if (!mem.findBlock(triggerAddr)) { stopReason = "unmapped payload trigger"; stopAtTrigger = triggerAddr; break; }
                // FIX: VTable special handling 제거. 진짜 SC chain 은 vartrigger base 로 jump 하고
                // 그것을 일반 trigger 처럼 처리. eudplib EUDVariable.GetVTable() = self._vartrigger (= trigger struct base).
                // VTable hack 제거 후 일반 trigger 처리 일관.
                execAddr = triggerAddr + kChkOffset;
                nextAddrLoc = triggerAddr + kNextOffset;
                payloadHits++;
            }

            // 루프 감지 / 진단: 방문 카운트 항상 기록 (top-visited 로 루프 head 식별)
            {
                int& vc = visitCount[triggerAddr];
                vc++;
                if (kPerTrigVisitCap > 0 && vc > kPerTrigVisitCap) {
                    stopReason = "per-trigger visit cap";
                    stopAtTrigger = triggerAddr;
                    break;
                }
            }

            if (!isVTable) {
                try {
                    emu.executeTriggerAt(execAddr);
                } catch (...) {}
            }
            totalTriggers++;

            uint32_t nextAddr;
            try { nextAddr = mem.readU32(nextAddrLoc); }
            catch (...) { stopReason = "nextAddr read fail"; stopAtTrigger = triggerAddr; break; }
            if (visited.count(nextAddr) && nextAddr == triggerAddr) {
                stopReason = "self-loop"; stopAtTrigger = triggerAddr; break;
            }
            // FIX: nextAddr == 0 인 경우 lenient mode 가 0 위치에 page alloc → garbage trigger 실행.
            //   진짜 chain 끝 (= nextptr=0) 으로 인식하고 break.
            if (nextAddr == 0) { stopReason = "nextAddr=0 (end of chain)"; stopAtTrigger = triggerAddr; break; }
            // FIX: SC init_triggers_list terminator — `(trig_addr & 0x1) != 0` 이면 terminal.
            //   SC engine 은 LSB=1 인 next_ptr 를 chain end sentinel 로 인식.
            //   ~(PTS+4) 도 LSB=1 (PTS+4 가 even). odd low-addr 도 terminator.
            if (nextAddr & 0x1u) {
                stopReason = "LSB=1 terminator (SC sentinel)";
                stopAtTrigger = triggerAddr;
                break;
            }
            // FIX: SC chain end sentinel — 옛 코드 RunTriggerEngine 의:
            //   for (; (trigaddr < 0x80000000) || (trigaddr != ~(PTS+4)); ...)
            // = trigaddr >= 0x80000000 일 때 high-address sentinel. chk[last].next_ptr = ~(PTS+4)
            // 가 set 되어 있으면 = 정상 frame 종료. 우리도 인식해야 chain 무한 loop 방지.
            if (nextAddr >= 0x80000000u) {
                stopReason = "high-addr sentinel (frame complete)";
                stopAtTrigger = triggerAddr;
                break;
            }
            triggerAddr = nextAddr;
            safetyCount++;
        }
        if (triggerAddr == ptsAddr) { stopReason = "PTS sentinel (frame complete)"; }
        else if (safetyCount >= maxTriggersPerPlayer) { stopReason = "maxTriggersPerPlayer cap"; }
        if (g_melterVerbose) {
            std::fprintf(stderr, "[pts_runner] player %d STOPPED: %s  (trigCount=%llu, stopAt=0x%08X)\n",
                         player, stopReason, (unsigned long long)safetyCount, stopAtTrigger);
            if (payloadHits > 0) {
                std::fprintf(stderr, "[pts_runner] player %d reached payload region %d times\n",
                             player, payloadHits);
                if (player == 0) {
                    // visit count distribution for player 0
                    std::vector<std::pair<uint32_t,int>> vv(visitCount.begin(), visitCount.end());
                    std::sort(vv.begin(), vv.end(), [](const auto&a, const auto&b){return a.second>b.second;});
                    std::fprintf(stderr, "[pts_runner] player 0 top 10 visited triggers:\n");
                    for (size_t k=0; k<std::min<size_t>(10,vv.size()); ++k) {
                        std::fprintf(stderr, "  0x%08X × %d\n", vv[k].first, vv[k].second);
                    }
                    std::fprintf(stderr, "  total distinct: %zu\n", vv.size());
                }
            }
        }
        if (safetyCount >= maxTriggersPerPlayer) {
            res.hitTriggerCap = true;
        }
        // 옛 코드 line 705 — 매 player chain 끝에 game tick increment
        try {
            uint32_t prevTick = mem.readU32(sc::GameTick);
            mem.writeU32(sc::GameTick, prevTick + 1);
        } catch (...) {}
    }

    res.triggersExecuted = static_cast<int>(totalTriggers);
    res.actionsExecuted = static_cast<int>(emu.actionsExecuted());

    // 4) runtime trigger 메모리에서 chk_data 부분 (2400 byte) 만 추출
    res.decryptedTrig.assign(chkTrigPayload.size(), 0);
    for (int i = 0; i < n; ++i) {
        uint32_t triggerAddr = runtimeBase + uint32_t(i) * kRuntimeTriggerSize;
        std::vector<uint8_t> chkData = mem.readBytes(triggerAddr + kChkOffset, kChkTrigSize);
        std::memcpy(res.decryptedTrig.data() + i * kChkTrigSize, chkData.data(), kChkTrigSize);
    }

    // RuntimeTRIG base 를 mem 의 metadata 에 노출 — multi-frame 이 재진입 시 사용
    res.runtimeBase = runtimeBase;
    res.runtimeSize = runtimeSize;

    // 5) decrypted 카운트
    for (int i = 0; i < n; ++i) {
        uint32_t origFlag, newFlag;
        std::memcpy(&origFlag, chkTrigPayload.data() + i * kChkTrigSize + 2368, 4);
        std::memcpy(&newFlag,  res.decryptedTrig.data() + i * kChkTrigSize + 2368, 4);
        if ((origFlag & 0x80000000u) && !(newFlag & 0x80000000u)) {
            res.triggersDecrypted++;
        }
    }
    return res;
}

// 한 프레임만 실행 — 메모리는 이미 setup 됐다고 가정 (runtime trigger / PTS 모두 매핑됨).
// 매 프레임 종료 후 PTS chain 의 nextptr 들은 OS modified 상태 유지 (eudplib payload 의
// 자기-수정 로직이 누적 효과 누림).
static uint64_t runOneFrame(VMemory& mem, TrigEmulator& emu,
                            uint32_t runtimeBase, uint32_t runtimeSize,
                            uint64_t maxTriggersPerPlayer) {
    uint64_t totalTriggers = 0;
    for (int player = 0; player < 8; ++player) {
        mem.writeU32(sc::CurrentPlayer, uint32_t(player));
        uint32_t ptsAddr = sc::PlayerTrigStructBase + uint32_t(player) * 12;
        uint32_t triggerAddr = mem.readU32(ptsAddr + 8);

        uint64_t safetyCount = 0;
        std::map<uint32_t, int> visitCount;
        const int kPerTrigVisitCap = 0;  // 0 = disabled — chain 무한 진행, cap 으로만 break
        while (triggerAddr != ptsAddr && safetyCount < maxTriggersPerPlayer) {
            bool inRuntime = (triggerAddr >= runtimeBase &&
                              triggerAddr < runtimeBase + runtimeSize &&
                              (triggerAddr - runtimeBase) % kRuntimeTriggerSize == 0);
            uint32_t execAddr, nextAddrLoc;
            if (inRuntime) {
                execAddr = triggerAddr + kChkOffset;
                nextAddrLoc = triggerAddr + kNextOffset;
            } else {
                if (!mem.findBlock(triggerAddr)) break;
                execAddr = triggerAddr + kChkOffset;
                nextAddrLoc = triggerAddr + kNextOffset;
            }
            if (kPerTrigVisitCap > 0) {
                int& vc = visitCount[triggerAddr];
                vc++;
                if (vc > kPerTrigVisitCap) break;
            }
            try { emu.executeTriggerAt(execAddr); } catch (...) {}
            totalTriggers++;
            uint32_t nextAddr;
            try { nextAddr = mem.readU32(nextAddrLoc); }
            catch (...) { break; }
            if (nextAddr == 0) break;
            if (nextAddr & 0x1u) break;          // FIX: SC LSB=1 terminator
            if (nextAddr >= 0x80000000u) break;  // FIX: high-addr sentinel = chain end
            triggerAddr = nextAddr;
            safetyCount++;
        }
    }
    return totalTriggers;
}

PtsRunResult runPtsFlowMultiFrame(const std::vector<uint8_t>& chkTrigPayload,
                                  VMemory& mem, TrigEmulator& emu,
                                  int numFrames,
                                  uint64_t maxTriggersPerPlayer) {
    // 1) Setup — runPtsFlow 첫 단계를 재사용 (할당 + chk 복사 + PTS 구축)
    PtsRunResult res = runPtsFlow(chkTrigPayload, mem, emu, maxTriggersPerPlayer);

    // res.decryptedTrig 가 첫 frame 결과. 이미 decrypted 가 있으면 빠른 종료.
    if (res.triggersDecrypted > 0) {
        std::fprintf(stderr, "[multi-frame] decrypted in frame 1: %d\n", res.triggersDecrypted);
        return res;
    }

    int n = static_cast<int>(chkTrigPayload.size() / kChkTrigSize);
    if (n == 0) return res;

    // 2) frame 2..N 반복
    for (int frame = 2; frame <= numFrames; ++frame) {
        // Advance the SC game tick (0x57F23C = sc::GameTick) so EUDDoEvents / frame-gated
        // polling can progress on the next iteration.
        // (Was advancing 0x6D0F18 = IsReplayFlag+4 — a mis-identified address. Per BWAPI
        //  Replay.h, 0x6D0F30 is the ReplayHeader; 0x6D0F14/0x6D0F18 sit before it and are
        //  NOT the frame counter. eudplib's confirmed game tick is 0x57F23C.)
        try { mem.writeU32(sc::GameTick, (uint32_t)frame); }
        catch (...) {}

        uint64_t frameExec = runOneFrame(mem, emu,
                                          res.runtimeBase, res.runtimeSize,
                                          maxTriggersPerPlayer);
        res.triggersExecuted += static_cast<int>(frameExec);

        // 매 frame 후 decryption 진행 체크
        int decryptedNow = 0;
        int changedBytes = 0;
        for (int i = 0; i < n; ++i) {
            uint32_t origFlag;
            std::memcpy(&origFlag, chkTrigPayload.data() + i * kChkTrigSize + 2368, 4);
            if (!(origFlag & 0x80000000u)) continue;
            uint32_t triggerAddr = res.runtimeBase + uint32_t(i) * kRuntimeTriggerSize;
            std::vector<uint8_t> chkData;
            try { chkData = mem.readBytes(triggerAddr + kChkOffset, kChkTrigSize); }
            catch (...) { continue; }
            uint32_t newFlag;
            std::memcpy(&newFlag, chkData.data() + 2368, 4);
            if (!(newFlag & 0x80000000u)) decryptedNow++;
            for (int b = 0; b < (int)kChkTrigSize; ++b) {
                if (chkData[b] != chkTrigPayload[i*kChkTrigSize + b]) {
                    changedBytes++;
                    break;  // 한 트리거당 하나만 카운트
                }
            }
        }
        std::fprintf(stderr, "[multi-frame] frame %d: %llu execs | %d/16 enc trigs touched | %d decrypted\n",
                     frame, (unsigned long long)frameExec, changedBytes, decryptedNow);

        if (decryptedNow == 16) {
            res.triggersDecrypted = decryptedNow;
            break;
        }
    }

    // 최종 추출
    res.decryptedTrig.assign(chkTrigPayload.size(), 0);
    for (int i = 0; i < n; ++i) {
        uint32_t triggerAddr = res.runtimeBase + uint32_t(i) * kRuntimeTriggerSize;
        std::vector<uint8_t> chkData = mem.readBytes(triggerAddr + kChkOffset, kChkTrigSize);
        std::memcpy(res.decryptedTrig.data() + i * kChkTrigSize, chkData.data(), kChkTrigSize);
    }
    res.triggersDecrypted = 0;
    for (int i = 0; i < n; ++i) {
        uint32_t origFlag, newFlag;
        std::memcpy(&origFlag, chkTrigPayload.data() + i * kChkTrigSize + 2368, 4);
        std::memcpy(&newFlag, res.decryptedTrig.data() + i * kChkTrigSize + 2368, 4);
        if ((origFlag & 0x80000000u) && !(newFlag & 0x80000000u)) res.triggersDecrypted++;
    }
    return res;
}

#ifndef MELTER_PTS_RUNNER_H
#define MELTER_PTS_RUNNER_H

#include <cstdint>
#include <vector>

class VMemory;
class TrigEmulator;

// PTS-based 트리거 실행 — SC 가 실제로 하는 방식.
//
// 흐름:
//   1) chk 의 TRIG payload (2400 byte × N) 를 runtime layout (2408 byte × N) 으로 변환
//      각 트리거: prev_ptr(4) + next_ptr(4) + chk_data(2400)
//   2) 각 player 0..7 에 대해 effPlayer 비트 검사해서 PTS linked list 구축
//   3) 각 player 에 대해:
//      - CurrentPlayer = player
//      - PTS[player].next_first → trigger 실행 → trigger.next_ptr → ... → 끝
//      - SetMemory(trigger+4, ...) 같은 ObfuscatedJump 가 next_ptr 변형해도 따라감
//
// 출력: 실행 후 runtime trigger 메모리에서 chk_data 부분 (2400 byte) 만 모아 반환.
//        freeze runtime 이 in-place 로 decryptTrigger 를 실행했다면 평문 트리거가 들어있음.

struct PtsRunResult {
    std::vector<uint8_t> decryptedTrig;  // 새 TRIG payload (chk layout, 2400 × N)
    int triggersDecrypted = 0;            // flag bit 31 가 클리어된 트리거 수
    int triggersExecuted = 0;
    int actionsExecuted = 0;
    bool hitTriggerCap = false;
    uint32_t runtimeBase = 0;             // runtime trigger 영역 시작 주소
    uint32_t runtimeSize = 0;
};

PtsRunResult runPtsFlow(const std::vector<uint8_t>& chkTrigPayload,
                        VMemory& mem, TrigEmulator& emu,
                        uint64_t maxTriggersPerPlayer = 100000,
                        int maxPlayers = 8);

// 멀티프레임 실행 — SC 가 매 frame 마다 PTS chain 을 처음부터 다시 도는 것을 흉내.
// freeze runtime 이 mix() 를 frame 분산 하면 한 frame 으로는 cryptKey 못 만듦.
// numFrames 동안 반복 실행하고, 매 frame 후 어떤 encrypted trigger 라도 byte 가 바뀌면
// (decryptTrigger 가 fire 한 신호) 카운트.
PtsRunResult runPtsFlowMultiFrame(const std::vector<uint8_t>& chkTrigPayload,
                                  VMemory& mem, TrigEmulator& emu,
                                  int numFrames,
                                  uint64_t maxTriggersPerPlayer = 100000);

#endif

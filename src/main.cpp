// ============================================================================
//  melter — freeze-protected StarCraft: Remastered 맵 해제 CLI
// ============================================================================
//
//  freeze 보호는 두 자물쇠를 겹쳐 채운다:
//    (A) 트리거 암호화   — 게임 트리거를 actualKey 로 XOR 암호화.
//    (B) obf-jump 난독화  — 복호화기의 점프 목적지를 매 프레임 "맵 지문(cryptKey)"으로
//                           재계산한다. 한 바이트만 고쳐도 점프가 어긋나므로 "편집 금지"가
//                           강제된다 (이게 freeze 의 진짜 핵심 보호).
//
//  melter 의 해제(패치) — 전부 scenario.chk 바이트 수정:
//    ① 복호화  : VM 을 1프레임 돌려 freeze 가 스스로 키를 메모리에 만들게 한 뒤,
//                "복호화 루프가 키를 슬롯에 self-modify 로 반복 복사한다"는 디컴파일
//                통찰(self-mod 체인)로 키 슬롯을 짚어 actualKey 를 복구한다.
//                브루트포스도, 전체 메모리 스캔도 아니다. 그 키로 트리거를 XOR 복호화.
//    ② defang  : obf-jump 슬롯을 진짜 목적지 R 로 정적 고정하고 재계산/흔들림을
//                무력화 → cryptKey 와 무관해져서 편집해도 안 깨진다.
//    ③ in-place: 패치된 scenario.chk 를 원본 MPQ 구조(블록 테이블)를 보존하며 다시
//                써넣는다 → 게임이 정상적으로 맵을 읽는다.
//
//  사용법:
//    melter <map.scx>                       복호화 + defang + in-place → <map>.unfrozen.scx
//    melter <map.scx> --rename-hex <hex>    위 + 맵 제목 변경(UTF-8 hex, 길이 보존)
//    melter <map.scx> --decompile           freeze.py 함수 카테고리 해체 리포트만 출력
//    melter <map.scx> --chk-only            복호화한 scenario.chk 만 출력 (defang/repack 안 함)
//    옵션: --verbose(저수준 진단 출력), --no-pause(끝나면 바로 종료), -h
//
//  종료 코드: 0 성공 / 2 오류 / 3 freeze 맵 아님
// ============================================================================

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

#include "chk_parse.h"        // findTrigSectionOffset, replaceTrigSection
#include "cmpdcmp.h"          // compressToBlock (in-place 재압축)
#include "debug_log.h"        // g_melterVerbose (저수준 모듈 진단 출력 스위치)
#include "eudplib_layout.h"   // analyzeEudplibPayload, EudplibPayloadLayout
#include "file_io.h"          // readAllBytes, parentDirectory, joinPath, ...
#include "freeze_crypt.h"     // freezeMix (mix2)
#include "freeze_decrypt.h"   // findEncryptedTriggers, decryptAllTriggers, validateKeyAgainst, kTriggerSize
#include "freeze_keys.h"      // parseFreezeMarker, FreezeKeys
#include "mpq_writer.h"       // writeStandardMpq
#include "mpqcrypt.h"         // HashString, DecryptData
#include "mpqread.h"          // MpqRead, HashTableEntry, BlockTableEntry
#include "pts_runner.h"       // runPtsFlow, PtsRunResult
#include "trig_emulate.h"     // TrigEmulator
#include "vmemory.h"          // VMemory

// debug_log.h 의 전역 스위치 정의 (외부 링크). --verbose 로 켜면 저수준 모듈이
// 내부 동작을 stderr 로 찍는다. 기본은 조용.
bool g_melterVerbose = false;

namespace {

// ──────────────────────────── 출력 경로 / 포맷 ────────────────────────────

std::string deriveOutputPath(const std::string& input, bool chkOnly) {
    std::string dir = parentDirectory(input);
    std::string base = fileBaseName(input);
    std::string ext = chkOnly ? ".chk" : fileExtension(input);
    if (ext.empty()) ext = ".scx";
    std::string name = base + (chkOnly ? "" : ".unfrozen") + ext;
    return dir.empty() ? name : joinPath(dir, name);
}

void pauseForReview() { std::cout << "\nPress Enter to close..."; std::cin.get(); }

std::string fmtSecs(double s) {
    char buf[64];
    if (s < 1.0)     std::snprintf(buf, sizeof(buf), "%.0fms", s * 1000);
    else if (s < 60) std::snprintf(buf, sizeof(buf), "%.2fs", s);
    else             std::snprintf(buf, sizeof(buf), "%.0fm%02.0fs", std::floor(s / 60), std::fmod(s, 60));
    return buf;
}

// ───────────────── Step 1-2: MPQ + scenario.chk + 암호화 트리거 ─────────────────

struct ExtractedMap {
    std::vector<uint8_t> chk;                       // 평문 scenario.chk
    std::vector<uint8_t> trig;                      // TRIG payload (복호화/defang 후 대체)
    size_t trigChkOffset = 0;                       // chk 안 TRIG payload 시작 offset
    size_t trigPayloadSize = 0;
    std::vector<size_t> encrypted;                  // trig 안에서 암호화된 트리거 인덱스들
    bool freezeTrickUsed = false;
    // VM(keycalc)의 블록테이블 읽기용 MPQ 데이터
    std::vector<uint8_t> rawMpq;
    std::vector<HashTableEntry> hashTable;
    std::vector<BlockTableEntry> blockTableFull;    // FULL 블록 테이블 (freeze trick 의 -2 가 아닌 실제 count)
};

// MPQ 를 연다 (freeze trick 우선, 실패하면 일반 MPQ). scenario.chk + TRIG + 암호화 트리거 식별.
bool extractMap(const std::string& input, ExtractedMap& out) {
    for (bool freezeTrick : {true, false}) {
        try {
            MpqRead mpq(input, freezeTrick);
            std::vector<uint8_t> chk = mpq.getScenarioChkBytes();
            if (chk.empty()) continue;
            out.chk = std::move(chk);
            out.freezeTrickUsed = freezeTrick;
            try { out.hashTable = mpq.getHashTable(); } catch (...) {}
            // keycalc 가 전체 블록 테이블을 샘플링하므로 raw[0:blockCount*16] 에서 직접 복원.
            try {
                out.rawMpq = readAllBytes(input);
                if (out.rawMpq.size() >= 32) {
                    uint32_t blockCount = 0; std::memcpy(&blockCount, out.rawMpq.data() + 28, 4);
                    if (blockCount && (size_t)blockCount * 16 <= out.rawMpq.size()) {
                        std::vector<uint8_t> buf(out.rawMpq.begin(), out.rawMpq.begin() + (size_t)blockCount * 16);
                        DecryptData(buf.data(), (uint32_t)buf.size(), HashString("(block table)", MPQ_HASH_FILE_KEY));
                        out.blockTableFull.resize(blockCount);
                        std::memcpy(out.blockTableFull.data(), buf.data(), buf.size());
                    }
                }
            } catch (...) {}
            break;
        } catch (const std::exception&) { /* 다음 trick 시도 */ }
    }
    if (out.chk.empty()) return false;
    out.trigChkOffset = findTrigSectionOffset(out.chk, out.trigPayloadSize);
    if (out.trigChkOffset == std::numeric_limits<size_t>::max()) { std::cerr << "No TRIG section\n"; return false; }
    out.trig.assign(out.chk.begin() + out.trigChkOffset, out.chk.begin() + out.trigChkOffset + out.trigPayloadSize);
    out.encrypted = findEncryptedTriggers(out.trig);
    return true;
}

// ──────────────────────────── obf-jump 자동 탐지 ────────────────────────────
//  (1) 정적 스캔: payload chk 에서 oJumperArray 후보 — decode(v)=v*4+0x58A364 가 payload 주소
//      범위에 드는 dword 가 >=2개 연속되고 0 으로 끝나는 run. 슬롯들이 decode 값.
//      (시그니처가 항상 유일하진 않아 후보를 모은 뒤 (2)로 거른다.)
//  (2) VM 1프레임 추적: 각 슬롯 트리거(slot+4)가 실제 실행되고 다음 실행 트리거의 주소-8 = 진짜
//      점프 목적지 R. 모든 슬롯이 R 로 풀리는 후보만 진짜 oJumperArray.
//  이후 6개 self-modify r-amount 는 고정 공식: +r at slot+344, -r at R+348.
struct ObjumpInfo {
    bool valid = false;
    size_t arrayChkOff = 0;          // oJumperArray[0] 의 chk offset
    int nSlots = 0;
    std::vector<uint32_t> slots;     // obf-jump nextptr 슬롯 주소들
    std::vector<uint32_t> targets;   // 각 슬롯의 진짜 점프 목적지 R
};

// ──────────────────────────── 공유 VM 1프레임 ────────────────────────────
// VM 을 1프레임 돌리는 것이 이 도구의 가장 무거운 작업(≈650만 트리거 실행, ~5s)이다.
// 키 복구와 obf-jump 탐지는 둘 다 "payload 실행 흐름"에만 의존하므로, 같은 1프레임의
// 실행 로그(setMemoryLog/trigExecLog) 를 공유한다 → 예전처럼 각자 1프레임씩 두 번 돌리지
// 않아 시간이 절반으로 준다. 반드시 **복호화 전, 암호화된 m.trig 위**에서 돌려야 한다:
// 키 검증(validateKeyAgainst)은 암호문을 복호화해 보는 것이라 평문이면 실패하기 때문.
//   wantSetMemLog=false (암호화 트리거 0개 = defang 전용 맵) 면 setMemoryLog 를 끄고
//   trigExecLog 만 → 불필요한 메모리/시간 절약.
void runVmOnce(const ExtractedMap& m, VMemory& mem, TrigEmulator& emu, bool wantSetMemLog) {
    emu.initStaticAreas(); emu.setDefaultCondTrue(false); emu.setAutoDisableBit(false);
    mem.setLenientMode(true);
    emu.loadChkSectionData(m.chk);
    if (m.rawMpq.size() >= 32 && !m.blockTableFull.empty()) {
        uint8_t hdr[32]; std::memcpy(hdr, m.rawMpq.data(), 32);
        try { emu.mockStormMpqHandle(hdr, m.hashTable, m.blockTableFull, m.rawMpq); } catch (...) {}
    }
    if (wantSetMemLog) emu.enableSetMemoryLog(true);
    emu.enableTriggerExecLog(true);
    runPtsFlow(m.trig, mem, emu, 20000000ull, 1);
}

ObjumpInfo detectObjump(const ExtractedMap& m, const EudplibPayloadLayout& L, TrigEmulator& emu) {
    ObjumpInfo info;
    if (!L.valid || L.payloadSize == 0 || m.chk.size() < 4) return info;
    const uint32_t PB = L.payloadMemoryAddr;
    const uint32_t PE = (uint32_t)(L.payloadMemoryAddr + L.payloadSize);
    auto decode = [&](uint32_t v) -> uint32_t { return (uint32_t)((uint64_t)v * 4ull + 0x58A364u); };
    auto u32at  = [&](size_t off) -> uint32_t { uint32_t v; std::memcpy(&v, m.chk.data() + off, 4); return v; };

    // (1) 0-종료 run(>=2 payload-decoding dword) 후보 수집 (byte-aligned).
    const size_t payChkStart = L.strxChkOffset + L.payloadStrxOffset;
    const size_t payChkEnd   = std::min(payChkStart + L.payloadSize, m.chk.size());
    if (payChkStart + 4 > payChkEnd) return info;
    std::vector<std::pair<size_t, std::vector<uint32_t>>> cands;
    for (size_t i = payChkStart; i + 4 <= payChkEnd; ) {
        if (decode(u32at(i)) >= PB && decode(u32at(i)) < PE) {
            std::vector<uint32_t> run; size_t j = i;
            while (j + 4 <= payChkEnd) { uint32_t s = decode(u32at(j)); if (s >= PB && s < PE) { run.push_back(s); j += 4; } else break; }
            bool term = (j + 4 <= payChkEnd && u32at(j) == 0);
            if (run.size() >= 2 && term) cands.push_back({ i, run });
            i = j;
        } else i += 1;
    }
    if (cands.empty()) return info;

    // (2) 공유 VM 1프레임(runVmOnce)의 실행 로그 사용: 각 실행 트리거의 "다음 실행 트리거 주소".
    const auto& te = emu.trigExecLog();
    std::unordered_map<uint32_t, uint32_t> nextOf;       // execAddr -> 첫 next-executed addr
    nextOf.reserve(te.size() * 2 + 16);
    for (size_t k = 0; k + 1 < te.size(); ++k) nextOf.emplace(te[k].addr, te[k + 1].addr);

    // (3) 모든 슬롯이 payload 목적지 R(=next-8)로 풀리는 후보 = 진짜 oJumperArray.
    int bestVer = 0;
    for (auto& c : cands) {
        std::vector<uint32_t> R(c.second.size(), 0); int ver = 0;
        for (size_t s = 0; s < c.second.size(); ++s) {
            auto it = nextOf.find(c.second[s] + 4);
            if (it != nextOf.end()) { uint32_t r = it->second - 8; if (r >= PB && r < PE) { R[s] = r; ++ver; } }
        }
        if (ver == (int)c.second.size() && ver > bestVer) {
            bestVer = ver; info.arrayChkOff = c.first; info.slots = c.second; info.targets = R; info.nSlots = (int)R.size();
        }
    }
    if (bestVer == 0) return info;
    info.valid = true;
    std::printf("  [defang] oJumperArray @chk 0x%zX, %d obf-jump(s):", info.arrayChkOff, info.nSlots);
    for (size_t s = 0; s < info.slots.size(); ++s) std::printf(" 0x%08X->R0x%08X", info.slots[s], info.targets[s]);
    std::printf("\n");
    return info;
}

// ─────────────────── 맵 제목 문자열 위치 (--rename-hex 용) ───────────────────
// SPRP 의 scenario-name 인덱스(u16) → STR(16bit) / STRx(32bit, EUD맵) 오프셋 테이블 → 문자열.
// chk 안 byte offset + 현재 byte 길이(종료 null 제외)를 반환.
bool findMapNameString(const std::vector<uint8_t>& chk, size_t& outOff, size_t& outLen) {
    auto rd32 = [&](size_t o) { uint32_t v; std::memcpy(&v, chk.data() + o, 4); return v; };
    auto rd16 = [&](size_t o) { uint16_t v; std::memcpy(&v, chk.data() + o, 2); return v; };
    size_t sprpOff = 0, strxOff = 0, strxSz = 0, strOff = 0, strSz = 0; bool haveSprp = false;
    for (size_t p = 0; p + 8 <= chk.size(); ) {
        int32_t sz; std::memcpy(&sz, chk.data() + p + 4, 4);
        size_t data = p + 8;
        size_t adv = (sz < 0) ? 0 : (size_t)sz;
        if (data + adv > chk.size()) adv = chk.size() - data;
        if      (std::memcmp(chk.data() + p, "SPRP", 4) == 0) { sprpOff = data; haveSprp = true; }
        else if (std::memcmp(chk.data() + p, "STRx", 4) == 0) { strxOff = data; strxSz = adv; }
        else if (std::memcmp(chk.data() + p, "STR ", 4) == 0) { strOff  = data; strSz  = adv; }
        p = data + adv;
    }
    if (!haveSprp || sprpOff + 2 > chk.size()) return false;
    uint16_t nameIdx = rd16(sprpOff);
    if (nameIdx == 0) return false;                      // 0 = 기본 이름 (테이블에 없음)
    size_t s;
    if (strxOff && strxSz >= 4) {                        // STRx: u32 count, u32 offsets
        uint32_t cnt = rd32(strxOff);
        if (nameIdx > cnt) return false;
        size_t e = strxOff + 4 + (size_t)(nameIdx - 1) * 4;
        if (e + 4 > chk.size()) return false;
        s = strxOff + rd32(e);
    } else if (strOff && strSz >= 2) {                   // STR: u16 count, u16 offsets
        uint16_t cnt = rd16(strOff);
        if (nameIdx > cnt) return false;
        size_t e = strOff + 2 + (size_t)(nameIdx - 1) * 2;
        if (e + 2 > chk.size()) return false;
        s = strOff + rd16(e);
    } else return false;
    if (s >= chk.size()) return false;
    size_t e = s; while (e < chk.size() && chk[e] != 0) ++e;
    outOff = s; outLen = e - s; return true;
}

// ──────────────── --decompile: freeze.py 함수 카테고리 해체 리포트 ────────────────
// VM 1프레임을 돌려, 각 writer 트리거를 "주로 쓰는 메모리 영역"으로 분류한다:
//   RT-TRIG(0x21000000)=decryptTrigger / CurrentPlayer(0x6509B0)=EUDFunc-dispatch /
//   DeathTable=원본 game-logic / payload(0x19xx)=VProc·assigner / 블록테이블 read=keycalc.
void decompileReport(const ExtractedMap& m) {
    VMemory mem; TrigEmulator emu(mem);
    emu.initStaticAreas(); emu.setDefaultCondTrue(false); emu.setAutoDisableBit(false); mem.setLenientMode(true);
    emu.loadChkSectionData(m.chk);
    if (m.rawMpq.size() >= 32 && !m.blockTableFull.empty()) {
        uint8_t hdr[32]; std::memcpy(hdr, m.rawMpq.data(), 32);
        try { emu.mockStormMpqHandle(hdr, m.hashTable, m.blockTableFull, m.rawMpq); } catch (...) {}
    }
    emu.enableSetMemoryLog(true); emu.enableTriggerExecLog(true);
    emu.watchReadRegion(0x60000000u, 0x60100000u);  // MPQ 블록 테이블 = keycalc 의 read
    runPtsFlow(m.trig, mem, emu, 20000000ull, 1);
    const auto& sm = emu.setMemoryLog();
    const auto& te = emu.trigExecLog();
    std::vector<uint32_t> ownerOf(sm.size(), 0);
    for (const auto& t : te) for (uint64_t k = t.setMemBegin; k < t.setMemEnd && k < sm.size(); ++k) ownerOf[k] = t.addr;
    auto da = [](uint16_t u, uint32_t p) { return 0x58A364u + (uint32_t)u * 48u + p * 4u; };
    struct P { uint64_t rt = 0, cp = 0, dt = 0, pay = 0, oth = 0, tot = 0; };
    std::map<uint32_t, P> prof;
    for (size_t i = 0; i < sm.size(); ++i) {
        uint32_t a = da(sm[i].unitID, sm[i].player1); P& p = prof[ownerOf[i]]; p.tot++;
        if (a >= 0x21000000u && a < 0x22000000u) p.rt++;
        else if (a == 0x6509B0u) p.cp++;
        else if (a >= 0x58A364u && a < 0x5993B4u) p.dt++;
        else if (a >= 0x19000000u && a < 0x1C000000u) p.pay++;
        else p.oth++;
    }
    std::map<std::string, uint64_t> catTrigs, catWrites; std::map<std::string, uint32_t> catSample;
    for (auto& kv : prof) {
        const P& p = kv.second; std::string cat;
        if (p.rt > 0)              cat = "decryptTrigger (runtime-TRIG decrypt)";
        else if (p.dt * 2 > p.tot) cat = "game-logic (original Deaths)";
        else if (p.cp * 2 > p.tot) cat = "EUDFunc-dispatch (f_setcurpl)";
        else if (p.pay * 2 > p.tot)cat = "VProc/assigner (variable ops/mix)";
        else                       cat = "other/mixed";
        catTrigs[cat]++; catWrites[cat] += p.tot;
        if (!catSample.count(cat) || p.tot > prof[catSample[cat]].tot) catSample[cat] = kv.first;
    }
    std::printf("\n=== DECOMPILE TEARDOWN (trigger stream -> freeze.py functions) ===\n");
    std::printf("VM ran %llu triggers; %zu distinct writer triggers; %zu total writes\n",
                (unsigned long long)emu.triggersExecuted(), prof.size(), sm.size());
    std::vector<std::pair<uint64_t, std::string>> order;
    for (auto& kv : catWrites) order.push_back({ kv.second, kv.first });
    std::sort(order.rbegin(), order.rend());
    std::printf("  %-38s %-9s %-10s %s\n", "freeze.py category", "triggers", "writes", "sample");
    for (auto& o : order)
        std::printf("  %-38s %-9llu %-10llu 0x%08X\n", o.second.c_str(),
                    (unsigned long long)catTrigs[o.second], (unsigned long long)o.first, catSample[o.second]);
    // keycalc 는 read-only 라 write 카테고리에 안 잡힘 → 블록테이블 read 로 별도 표시.
    const auto& rl = emu.readLog();
    if (!rl.empty()) {
        std::vector<uint32_t> rOwner(rl.size(), 0);
        for (const auto& t : te) for (size_t k = t.readBegin; k < t.readEnd && k < rl.size(); ++k) rOwner[k] = t.addr;
        std::map<uint32_t, uint64_t> kc;
        for (size_t i = 0; i < rl.size(); ++i) kc[rOwner[i]]++;
        uint32_t samp = kc.empty() ? 0 : kc.begin()->first;
        std::printf("  %-38s %-9zu %-10llu 0x%08X  (reads block table)\n",
                    "keycalc (MPQ checksum, read-only)", kc.size(), (unsigned long long)rl.size(), samp);
    }
}

// ─────────────── 복호화 키 복구 ① scan-free (self-mod 체인 랭킹) ───────────────
// 복호화 루프는 매 iteration actualKey 를 decryptTrigger 의 key 파라미터 슬롯에 "직접
// SetTo(mod 7)"로 복사한다(키는 loop-invariant). eudplib 의 변수 복사는 writer 트리거의
// value 필드(owner_exec+0x154)를 self-modify 하는 방식이라, 키는 같은 값을 가진 여러 슬롯을
// 거쳐 흐른다. 그래서 loop-invariant 후보들을 "값 보존 self-mod 체인 길이"로 랭킹하면
// 키가 사실상 1등으로 올라온다(데이터플로우로 구조적 식별 — 스캔 아님). 최종 확정은 그 맵의
// 암호화 트리거 전부로 검증(validateKeyAgainst). 보통 1~3번째 후보에서 바로 통과.
bool recoverKeyFromVm(const ExtractedMap& m, VMemory& mem, TrigEmulator& emu, uint32_t& outKey) {
    if (m.encrypted.empty()) return false;
    const auto& sm = emu.setMemoryLog();
    const auto& te = emu.trigExecLog();
    auto deathAddr = [](uint16_t u, uint32_t p) { return 0x58A364u + (uint32_t)u * 48u + p * 4u; };
    auto pay = [](uint32_t a) { return a >= 0x19000000u && a < 0x1C000000u; };
    std::vector<uint32_t> ownerOf(sm.size(), 0);
    for (const auto& t : te) for (uint64_t k = t.setMemBegin; k < t.setMemEnd && k < sm.size(); ++k) ownerOf[k] = t.addr;
    // mod-7 SetTo 로 payload 슬롯에 쓴 것: dest -> {value -> count}, 그리고 마지막 writer owner
    std::map<uint32_t, std::map<uint32_t, int>> dv;
    std::map<uint32_t, uint32_t> lastOwner;
    for (size_t i = 0; i < sm.size(); ++i) {
        if (sm[i].modifier != 7) continue;
        uint32_t d = deathAddr(sm[i].unitID, sm[i].player1);
        if (pay(d)) { dv[d][sm[i].value]++; lastOwner[d] = ownerOf[i]; }
    }
    // loop-invariant 후보: 한 값만, >=2회 쓰인 슬롯
    std::vector<std::pair<uint32_t, uint32_t>> cand;
    for (auto& kv : dv) if (kv.second.size() == 1 && kv.second.begin()->second >= 2) cand.push_back({ kv.first, kv.second.begin()->first });
    // 값 보존 self-mod 체인 길이: slot -> writer.valueField(owner+0x154) -> ... 같은 값이 유지되는 동안
    auto chainLen = [&](uint32_t s) -> int {
        std::set<uint32_t> seen; uint32_t cur = s, v = mem.readU32(s); int len = 0;
        while (seen.insert(cur).second && len < 200) {
            auto it = lastOwner.find(cur); if (it == lastOwner.end()) break;
            uint32_t vf = it->second + 0x154u;
            if (!pay(vf) || mem.readU32(vf) != v) break;
            cur = vf; ++len;
        }
        return len;
    };
    // 랭킹: 1차 체인 길이, 2차 non-trivial 값(키는 큰 랜덤 dword — 작은 카운터/주소 아님)
    auto nonTrivial = [&](uint32_t v) { return (v >= 0x10000u && !pay(v)) ? 1 : 0; };
    std::vector<std::tuple<int, int, uint32_t, uint32_t>> ranked;  // (chainLen, nonTrivial, slot, value)
    for (auto& c : cand) ranked.push_back(std::make_tuple(chainLen(c.first), nonTrivial(c.second), c.first, c.second));
    std::sort(ranked.rbegin(), ranked.rend());
    std::vector<const uint8_t*> encPtr;
    for (size_t idx : m.encrypted) encPtr.push_back(m.trig.data() + idx * kTriggerSize);
    auto crossAll = [&](uint32_t K) { for (auto* p : encPtr) if (!validateKeyAgainst(p, K)) return false; return true; };
    bool found = false; int rankPos = 0, chl = 0;
    for (size_t i = 0; i < ranked.size(); ++i)
        if (crossAll(std::get<3>(ranked[i]))) { outKey = std::get<3>(ranked[i]); chl = std::get<0>(ranked[i]); rankPos = (int)i + 1; found = true; break; }
    std::printf("  [decrypt] %zu loop-invariant candidates; ", cand.size());
    if (found) std::printf("actualKey=0x%08X (self-mod chain %d, rank #%d) — validated all %zu encrypted triggers, NO SCAN\n", outKey, chl, rankPos, encPtr.size());
    else std::printf("no candidate validated — falling back to memory scan\n");
    return found;
}

// ─────────────── 복호화 키 복구 ② fallback: 라이브 메모리 스캔 (브루트포스 아님) ───────────────
// actualKey 는 런타임에 메모리에 떠 있다. VM 1프레임 후 라이브 메모리의 모든 distinct dword
// (~80만개, 2^32 아님)을 키 후보로 보고 암호화 트리거 전부를 검증. strategyDecompile 이
// 실패할 때만 쓰는 안전망.
bool recoverKeyByMemScan(const ExtractedMap& m, VMemory& mem, uint32_t& outActualKey) {
    if (m.encrypted.empty()) return false;
    uint32_t cryptKey = 0;
    FreezeKeys keys{};
    if (parseFreezeMarker(m.rawMpq, keys)) cryptKey = keys.cryptKey;
    std::vector<const uint8_t*> encPtr;
    for (size_t idx : m.encrypted) encPtr.push_back(m.trig.data() + idx * kTriggerSize);
    std::unordered_set<uint32_t> cands; cands.reserve(1u << 20);
    for (const auto& kv : mem.allBlocks()) {
        const auto& blk = kv.second; size_t dwords = blk.data.size() / 4;
        for (size_t i = 0; i < dwords; ++i) { uint32_t v; std::memcpy(&v, blk.data.data() + i * 4, 4); cands.insert(v); }
    }
    auto crossAll = [&](uint32_t ak) { for (auto* p : encPtr) if (!validateKeyAgainst(p, ak)) return false; return true; };
    bool found = false;
    for (uint32_t K : cands) {
        if (validateKeyAgainst(encPtr[0], K) && crossAll(K)) { outActualKey = K; found = true; break; }
        uint32_t ak = freezeMix(K, cryptKey);  // K 가 raw triggerKeyVal 인 경우 actualKey=mix2(K,cryptKey)
        if (validateKeyAgainst(encPtr[0], ak) && crossAll(ak)) { outActualKey = ak; found = true; break; }
    }
    std::printf("  [memscan] scanned %zu dwords; %s\n", cands.size(), found ? "key found" : "key NOT found");
    return found;
}

// ──────────────────────────── in-place MPQ 패치 ────────────────────────────
// 패치된 scenario.chk 를 원본 MPQ 의 같은 블록에 다시 써넣되, 헤더/블록테이블/해시테이블/다른
// 블록은 그대로 둔다 → keycalc 가 읽는 데이터가 동일하게 유지되고 게임이 정상적으로 읽는다.
// 같은 비압축 크기 + 원본 압축 블록 슬랙 안에서만 가능(크기 보존). 슬랙 초과면 false.
bool writeInPlaceMpqPatch(const std::string& path, const ExtractedMap& m, const std::vector<uint8_t>& newChk) {
    if (m.rawMpq.size() < 32 || m.blockTableFull.empty() || m.hashTable.empty()) {
        std::cerr << "  [in-place] rawMpq/blockTable/hashTable 없음 — in-place 불가\n"; return false;
    }
    uint32_t ha = HashString("staredit\\scenario.chk", MPQ_HASH_NAME_A);
    uint32_t hb = HashString("staredit\\scenario.chk", MPQ_HASH_NAME_B);
    uint32_t blockIndex = 0xFFFFFFFFu;
    for (const auto& h : m.hashTable)
        if (h.hashA == ha && h.hashB == hb && h.blockIndex < 0xFFFFFFFEu) { blockIndex = h.blockIndex; break; }
    if (blockIndex >= m.blockTableFull.size()) { std::cerr << "  [in-place] scenario.chk 블록 못 찾음\n"; return false; }
    const BlockTableEntry& blk = m.blockTableFull[blockIndex];
    if (static_cast<size_t>(blk.blockOffset) + blk.blockSize > m.rawMpq.size()) { std::cerr << "  [in-place] 블록 범위 초과\n"; return false; }
    if (newChk.size() != blk.fileSize) {
        std::cerr << "  [in-place] CHK 크기 " << newChk.size() << " != 원본 " << blk.fileSize << " (in-place 는 동일 크기 필요)\n"; return false;
    }
    std::string compressed = compressToBlock(std::string(newChk.begin(), newChk.end()), MAFA_COMPRESS_STANDARD, MAFA_COMPRESS_STANDARD);
    std::printf("  [in-place] scenario.chk: 원본압축 %u, fileSize %u | 재압축 %zu\n", blk.blockSize, blk.fileSize, compressed.size());
    if (compressed.size() > blk.blockSize) { std::cerr << "  [in-place] 재압축(" << compressed.size() << ") > 원본 블록(" << blk.blockSize << ") — 슬랙 초과\n"; return false; }
    std::vector<uint8_t> out = m.rawMpq;
    std::memset(out.data() + blk.blockOffset, 0, blk.blockSize);
    std::memcpy(out.data() + blk.blockOffset, compressed.data(), compressed.size());
    std::remove(path.c_str());
    std::ofstream os(path, std::ios_base::binary);
    if (!os.is_open()) { std::cerr << "  [in-place] 출력 열기 실패: " << path << "\n"; return false; }
    os.write(reinterpret_cast<const char*>(out.data()), out.size());
    return os.good();
}

// ──────────────────────────── CLI 인자 ────────────────────────────
struct Args {
    std::string input, output;
    bool chkOnly = false;        // --chk-only: 복호화한 scenario.chk 만 출력 (defang/repack 안 함)
    bool decompile = false;      // --decompile: 해체 리포트만 출력
    bool doRename = false;       // --rename-hex <utf8hex>: 맵 제목 변경 (길이 보존)
    std::vector<uint8_t> renameBytes;
    bool pauseOnExit = true;     // --no-pause 면 false
    bool verbose = false;        // --verbose: 저수준 모듈 진단 출력(stderr) 켜기
    bool showHelp = false;       // -h / --help
};

void printHelp() {
    std::cout <<
        "melter — freeze unprotector for StarCraft maps\n\n"
        "Usage: melter <input.scx> [output.scx] [options]\n\n"
        "기본 동작: freeze 감지 -> 복호화 + obf-jump defang + in-place -> <input>.unfrozen.scx\n\n"
        "Options:\n"
        "  --decompile        트리거를 freeze.py 함수 카테고리로 분해한 해체 리포트만 출력\n"
        "  --rename-hex HEX   맵 제목을 UTF-8 hex 로 변경 (현재 제목 길이 이내)\n"
        "  --chk-only         복호화한 scenario.chk 만 출력 (defang/repack 안 함)\n"
        "  --verbose          저수준 모듈 진단 출력(stderr) 켜기\n"
        "  --no-pause         끝나면 바로 종료\n"
        "  -h, --help         도움말\n";
}

Args parseArgs(int argc, char** argv) {
    Args a;
    std::vector<std::string> pos;
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        if      (s == "--no-pause")  a.pauseOnExit = false;
        else if (s == "--verbose")   a.verbose = true;
        else if (s == "--chk-only")  a.chkOnly = true;
        else if (s == "--decompile") a.decompile = true;
        else if (s == "--rename-hex" && i + 1 < argc) {
            a.doRename = true;
            std::string h = argv[++i];
            for (size_t k = 0; k + 1 < h.size(); k += 2)
                a.renameBytes.push_back((uint8_t)std::strtoul(h.substr(k, 2).c_str(), nullptr, 16));
        }
        else if (s == "-h" || s == "--help") a.showHelp = true;
        else pos.push_back(s);
    }
    if (!pos.empty()) a.input = pos[0];
    if (pos.size() >= 2) a.output = pos[1];
    return a;
}

}  // namespace

// ============================================================================
//  main — 감지 → (복호화) → defang → in-place
// ============================================================================
int main(int argc, char** argv) {
#ifdef _WIN32
    SetConsoleOutputCP(65001);
#endif
    std::cout.setf(std::ios::unitbuf);
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    Args args = parseArgs(argc, argv);
    g_melterVerbose = args.verbose;
    if (args.showHelp || args.input.empty()) {
        printHelp();
        if (args.pauseOnExit && !args.showHelp) pauseForReview();
        return args.showHelp ? 0 : 1;
    }
    if (args.output.empty()) args.output = deriveOutputPath(args.input, args.chkOnly);

    int exitCode = 0;
    try {
        std::cout << "Input : " << args.input << "\nOutput: " << args.output << "\n\n";

        // ── Step 1-2: MPQ + scenario.chk + 암호화 트리거 ──
        std::cout << "[1/4] Extracting MPQ + scenario.chk + TRIG ...\n";
        ExtractedMap m;
        if (!extractMap(args.input, m)) throw std::runtime_error("scenario.chk 추출 실패");
        std::cout << "  freeze MPQ trick   : " << (m.freezeTrickUsed ? "yes" : "no") << "\n";
        std::cout << "  scenario.chk size  : " << m.chk.size() << " bytes\n";
        std::cout << "  TRIG triggers      : " << m.trig.size() / kTriggerSize << "\n";
        std::cout << "  encrypted triggers : " << m.encrypted.size() << "\n\n";

        // ── --decompile: 해체 리포트만 ──
        if (args.decompile) { decompileReport(m); if (args.pauseOnExit) pauseForReview(); return 0; }

        // ── 감지: marker 또는 암호화 트리거 ──
        FreezeKeys fk{};
        bool hasMarker = parseFreezeMarker(m.rawMpq, fk);
        bool isFreeze = hasMarker || !m.encrypted.empty();
        std::cout << "[2/4] freeze detection: " << (isFreeze ? "YES (frozen)" : "NO")
                  << "  (marker=" << (hasMarker ? "found" : "none") << ", encrypted=" << m.encrypted.size() << ")\n";
        if (!isFreeze) {
            std::cout << "  이 맵은 freeze 보호가 아닙니다 — 변환할 것이 없습니다.\n";
            if (args.pauseOnExit) pauseForReview();
            return 3;
        }

        // ── 공유 VM 1프레임 (키복구 + defang 이 함께 사용) ──
        // 가장 무거운 단계. 예전엔 복호화용·defang용 1프레임씩 두 번 돌려 ~2배 걸렸으나,
        // 둘 다 payload 실행 흐름만 보므로 한 번만 돌려 로그를 공유한다(시간 절반).
        // 반드시 복호화 전(암호화된 m.trig)에 돌린다 — 키 검증이 암호문을 필요로 함.
        VMemory mem; TrigEmulator emu(mem);
        auto tVm0 = std::chrono::steady_clock::now();
        runVmOnce(m, mem, emu, /*wantSetMemLog=*/!m.encrypted.empty());
        double vmElapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - tVm0).count();

        // ── 패치 ①: 복호화 (암호화 트리거가 있을 때만) ──
        std::string method;
        int decrypted = 0;
        if (!m.encrypted.empty()) {
            std::cout << "\n[3/4] Decrypting (scan-free, decompilation data-flow) ...\n";
            uint32_t actualKey = 0; bool found = false;
            if (recoverKeyFromVm(m, mem, emu, actualKey)) { found = true; method = "decompile"; }
            else if (recoverKeyByMemScan(m, mem, actualKey)) { found = true; method = "memscan"; }
            if (!found) throw std::runtime_error("키 복구 실패 (decompile + memscan 모두 실패)");
            decrypted = decryptAllTriggers(m.trig, actualKey);
            std::cout << "  actualKey 0x" << std::hex << actualKey << std::dec
                      << " — decrypted " << decrypted << "/" << m.encrypted.size()
                      << " in " << fmtSecs(vmElapsed) << " (1 VM frame, shared)\n";
        } else {
            std::cout << "\n[3/4] 암호화 트리거 0개 — 복호화 생략 (defang 만 적용)\n";
            method = "defang-only";
        }

        // ── 패치 ②: obf-jump defang (자동 탐지, 공유 VM 로그 사용) ──
        std::cout << "\n[4/4] Defanging obf-jumps + writing output ...\n";
        EudplibPayloadLayout L = analyzeEudplibPayload(m.chk);
        ObjumpInfo oj = detectObjump(m, L, emu);
        if (oj.valid) {
            auto memToChk = [&](uint32_t addr, size_t& off) -> bool {
                if (!L.valid || addr < L.payloadMemoryAddr) return false;
                off = L.strxChkOffset + L.payloadStrxOffset + (size_t)(addr - L.payloadMemoryAddr);
                return off + 4 <= m.chk.size();
            };
            // oJumperArray 전체(슬롯 N개 + 0 종료)를 0 으로 → initOffsets/encryptOffsets 무력화
            for (int k = 0; k <= oj.nSlots; ++k) {
                size_t a = oj.arrayChkOff + (size_t)k * 4;
                if (a + 4 <= m.chk.size()) { uint32_t z = 0; std::memcpy(m.chk.data() + a, &z, 4); }
            }
            // 각 슬롯을 진짜 목적지 R 로 고정 + self-modify amount(+r at slot+344, -r at R+348) 0
            for (int k = 0; k < oj.nSlots; ++k) {
                uint32_t slot = oj.slots[k], R = oj.targets[k]; size_t off;
                if (memToChk(slot, off)) std::memcpy(m.chk.data() + off, &R, 4);
                const uint32_t rAddr[2] = { slot + 344u, R + 348u };
                for (uint32_t ra : rAddr) { size_t roff; if (memToChk(ra, roff)) { uint32_t z = 0; std::memcpy(m.chk.data() + roff, &z, 4); } }
            }
            std::printf("  defanged %d obf-jump(s) — cryptKey-independent (edit-safe)\n", oj.nSlots);
        } else {
            std::cout << "  WARNING: obf-jump 자동 탐지 실패 — 편집 안정성은 보장 못 함 (복호화는 유효)\n";
        }

        // ── 출력: TRIG 교체 → (제목 변경) → in-place / chk ──
        std::vector<uint8_t> outChk = replaceTrigSection(m.chk, m.trig);

        if (args.doRename) {
            size_t noff = 0, nlen = 0;
            if (!findMapNameString(outChk, noff, nlen))
                std::cout << "  [rename] 맵 제목 문자열 없음 — 건너뜀\n";
            else if (args.renameBytes.size() > nlen)
                std::printf("  [rename] 새 제목(%zu B)이 현재 제목(%zu B)보다 김 — 건너뜀 (한글 1글자=3B)\n", args.renameBytes.size(), nlen);
            else {
                std::memcpy(outChk.data() + noff, args.renameBytes.data(), args.renameBytes.size());
                for (size_t k = args.renameBytes.size(); k < nlen; ++k) outChk[noff + k] = 0;  // null-pad
                std::printf("  [rename] 맵 제목 변경 (%zu -> %zu bytes)\n", nlen, args.renameBytes.size());
            }
        }

        if (args.chkOnly) {
            ensureDirectory(parentDirectory(args.output));
            std::ofstream os(args.output, std::ios::binary);
            os.write(reinterpret_cast<const char*>(outChk.data()), outChk.size());
            std::cout << "  wrote .chk: " << args.output << "\n";
            method += "+chk";
        } else if (writeInPlaceMpqPatch(args.output, m, outChk)) {
            std::cout << "  wrote in-place MPQ (freeze structure preserved): " << args.output << "\n";
            method += "+inplace";
        } else {
            std::cout << "  in-place 실패 — 일반 repack 으로 출력 (인게임 동작 보장 안 됨)\n";
            writeStandardMpq(args.output, outChk, {});
        }

        std::cout << "\n=== SUMMARY ===\n";
        std::cout << "  method   : " << method << "\n";
        std::cout << "  encrypted: " << m.encrypted.size() << "  (decrypted " << decrypted << ")\n";
        std::cout << "  output   : " << args.output << "\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        exitCode = 2;
    }
    if (args.pauseOnExit) pauseForReview();
    return exitCode;
}

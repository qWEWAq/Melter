#ifndef MELTER_VMEMORY_H
#define MELTER_VMEMORY_H

// VMemory: SC 의 32비트 가상 메모리를 시뮬레이트.
//
// 설계:
//   - 메모리는 disjoint 한 "블록" 들의 집합 (각 블록은 [start, start+size) 범위)
//   - std::map<uint32_t, Block> 로 startAddress 키로 정렬
//   - 조회: upper_bound 로 O(log N) — N은 블록 수 (보통 < 100)
//   - 이전 mpqtrig 의 per-byte hashmap 방식 대비 메모리 100~10000배 절약, 조회 빠름
//
// SC 의 실제 메모리 레이아웃은 sc_memory_layout.h 참고.

#include <cstdint>
#include <cstring>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

class VMemory {
public:
    struct Block {
        uint32_t start;   // [start, start+size) 가 블록의 가상 주소 범위
        uint32_t size;
        std::vector<uint8_t> data;
        std::string label;  // 디버그/로그용 (예: "TRIG", "DeathTable")
    };

    VMemory();
    ~VMemory();

    // 블록 정적 할당. 이미 겹치는 영역이 있으면 throw.
    void allocAt(uint32_t address, uint32_t size, const std::string& label = "");

    // 데이터로 채워서 할당.
    void allocAt(uint32_t address, const std::vector<uint8_t>& data, const std::string& label = "");

    // [address, address+size) 와 겹치는 모든 block 제거 (= STRx 전체 alloc 전 충돌 제거용)
    void deallocRange(uint32_t address, uint32_t size);

    // [startRange, endRange) 안에서 size 바이트의 첫 빈 공간에 동적 할당.
    // 반환값: 할당된 시작 주소.
    uint32_t allocDynamic(uint32_t size, uint32_t startRange = 0x50000000,
                          uint32_t endRange = 0x55000000,
                          const std::string& label = "");

    // 주소가 어느 블록에 속하는지 (없으면 nullptr).
    Block* findBlock(uint32_t address);
    const Block* findBlock(uint32_t address) const;

    // 메모리에 임의 너비로 쓰기 (리틀엔디언).
    void writeU8(uint32_t address, uint8_t value);
    void writeU16(uint32_t address, uint16_t value);
    void writeU32(uint32_t address, uint32_t value);
    void writeBytes(uint32_t address, const uint8_t* data, uint32_t size);
    void writeBytes(uint32_t address, const std::vector<uint8_t>& data);

    // 임의 너비 읽기.
    uint8_t  readU8(uint32_t address) const;
    uint16_t readU16(uint32_t address) const;
    uint32_t readU32(uint32_t address) const;
    std::vector<uint8_t> readBytes(uint32_t address, uint32_t size) const;

    // 디버그: 모든 블록 정보 출력 (stderr).
    void dumpBlocks() const;

    // 모든 블록의 const 참조 (분석 도구용).
    const std::map<uint32_t, Block>& allBlocks() const { return blocks_; }

    // 통계 — 할당된 블록 수, 총 메모리 사용량.
    size_t blockCount() const { return blocks_.size(); }
    size_t totalBytes() const;

    // 안전 모드: 매핑 안 된 주소 접근시 throw 대신 0 반환 / no-op (디버그용).
    void setLenientMode(bool lenient) { lenient_ = lenient; }

    // ─────────── Write tracking (디버그/분석용) ───────────
    // 활성화시 writeU8/16/32/Bytes 가 호출될 때마다 주소별 카운트 증가.
    void enableWriteTracking(bool enable) { trackWrites_ = enable; }
    const std::map<uint32_t, uint64_t>& writeCounts() const { return writeCounts_; }
    void clearWriteCounts() { writeCounts_.clear(); }

    // ─────────── Write history (slot value update 추적) ───────────
    // writeU32 가 호출될 때마다 (addr, prevValue, newValue) 기록.
    // 대용량 — 필터 set 지정 권장 (특정 주소만 기록).
    struct WriteRecord {
        uint32_t addr;
        uint32_t prevValue;
        uint32_t newValue;
        uint64_t seq;       // 글로벌 write 순서
    };
    void enableWriteHistory(bool on) { trackHistory_ = on; }
    // 필터: empty = 모든 주소 기록, non-empty = filter 안의 주소만 기록
    void setWriteHistoryFilter(const std::set<uint32_t>& addrs) { historyFilter_ = addrs; }
    const std::vector<WriteRecord>& writeHistory() const { return history_; }
    void clearWriteHistory() { history_.clear(); writeSeq_ = 0; }

    // ─────────── Dropped-write tracking (stale-value 진단용) ───────────
    // lenient 모드에서 write 가 silently drop 되는 두 경우를 기록:
    //   (1) UNMAPPED      — 주소가 어떤 block 에도 없음
    //   (2) STRADDLE      — 주소가 block 안에 있으나 width 가 block 끝을 넘음
    // 둘 다 "쓰기가 메모리에 반영 안 됨" = stale 값 retain 의 smoking gun.
    // 키 = address, value = (count, lastValue, width, wasUnmapped).
    struct DroppedWrite {
        uint64_t count = 0;
        uint32_t lastValue = 0;
        uint8_t  width = 0;        // 1/2/4 (writeU8/16/32) — bytes 면 0
        bool     unmapped = false; // true=UNMAPPED, false=STRADDLE(block 끝 초과)
    };
    void enableDroppedWriteTrack(bool on) { trackDropped_ = on; }
    const std::map<uint32_t, DroppedWrite>& droppedWrites() const { return droppedWrites_; }
    void clearDroppedWrites() { droppedWrites_.clear(); droppedWriteEvents_ = 0; }
    uint64_t droppedWriteEvents() const { return droppedWriteEvents_; }

private:
    // key = startAddress. value = block. lookup: upper_bound 의 prev 가 contains 후보.
    std::map<uint32_t, Block> blocks_;
    bool lenient_ = false;
    bool trackWrites_ = false;
    std::map<uint32_t, uint64_t> writeCounts_;
    bool trackHistory_ = false;
    std::set<uint32_t> historyFilter_;
    std::vector<WriteRecord> history_;
    uint64_t writeSeq_ = 0;
    bool trackDropped_ = false;
    std::map<uint32_t, DroppedWrite> droppedWrites_;
    uint64_t droppedWriteEvents_ = 0;
    // 내부 헬퍼 — lenient write drop 을 기록.
    void recordDrop(uint32_t address, uint32_t value, uint8_t width, bool unmapped);

    // 주소를 포함하는 블록의 iterator 를 찾음. blocks_.end() = 못 찾음.
    std::map<uint32_t, Block>::iterator findContaining(uint32_t address);
    std::map<uint32_t, Block>::const_iterator findContaining(uint32_t address) const;

    // size 바이트 쓰기를 위해 [address, address+size) 가 한 블록 안에 있는지 검증.
    Block& requireRange(uint32_t address, uint32_t size);
    const Block& requireRange(uint32_t address, uint32_t size) const;
};

#endif  // MELTER_VMEMORY_H

#ifndef CHKREPAIR_MPQREAD_H
#define CHKREPAIR_MPQREAD_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "mpqtypes.h"

class MpqReadImpl;

// MPQ 아카이브 리더.
//
// useFreezeTrick=true 이면 freeze 보호 특유의 구조를 가정한다:
//   - block table은 헤더가 가리키는 위치가 아니라 파일 offset=0 에서 읽음
//   - block table 엔트리 수는 (헤더값 - 2)
//   - sectorSizeShift != 3 이어도 거절하지 않음
//
// useFreezeTrick=false 이면 표준 MPQ로 처리한다.
class MpqRead {
public:
    MpqRead(const std::string& mpqName, bool useFreezeTrick);
    ~MpqRead();

    int getHashEntryCount() const;
    const HashTableEntry* getHashEntry(int index) const;
    const HashTableEntry* getHashEntryByName(const std::string& fname) const;
    const BlockTableEntry* getBlockEntry(int index) const;

    // 블록을 복호화해서 반환 (압축은 풀지 않음). 실패시 빈 문자열.
    std::string getBlockContent(const HashTableEntry* hashEntry) const;

    // staredit\scenario.chk 의 원시(복호화 + 압축해제) chk 바이트.
    // 못 찾거나 디코드 실패시 빈 벡터.
    std::vector<uint8_t> getScenarioChkBytes() const;

    // 임의 파일을 이름으로 읽어 (복호화 + 압축해제) 한 바이트 반환.
    // 못 찾거나 디코드 실패시 빈 벡터.
    std::vector<uint8_t> readFile(const std::string& fname) const;

    // freeze Storm-mock 용 — decrypted hash/block table 전체 복사 반환.
    std::vector<HashTableEntry> getHashTable() const;
    std::vector<BlockTableEntry> getBlockTable() const;
    // MPQ raw 헤더 32바이트 반환.
    std::vector<uint8_t> getRawHeader() const;

private:
    std::unique_ptr<MpqReadImpl> pimpl;
};

using MpqReadPtr = std::shared_ptr<MpqRead>;

// scenario.chk 의 표준 해시 (정규 파일명 "staredit\scenario.chk")
constexpr uint32_t kScenarioChkHashA = 0xB701656E;
constexpr uint32_t kScenarioChkHashB = 0xFCFB1EED;

#endif  // CHKREPAIR_MPQREAD_H

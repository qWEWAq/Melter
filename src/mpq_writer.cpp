#include "mpq_writer.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "cmpdcmp.h"
#include "mpqcrypt.h"
#include "mpqtypes.h"

namespace {

// 2의 제곱 중 needle 이상인 최소값. 최소 16.
uint32_t roundUpPow2(uint32_t needle) {
    uint32_t v = 16;
    while (v < needle) v <<= 1;
    return v;
}

void writeFreshHashEntry(HashTableEntry& entry, const std::string& fname,
                         uint16_t locale, uint16_t platform, uint32_t blockIndex) {
    entry.hashA = HashString(fname.c_str(), MPQ_HASH_NAME_A);
    entry.hashB = HashString(fname.c_str(), MPQ_HASH_NAME_B);
    entry.language = locale;
    entry.platform = static_cast<uint8_t>(platform);
    entry.unused0 = 0;
    entry.blockIndex = blockIndex;
}

}  // namespace

void writeStandardMpq(const std::string& path,
                      const std::vector<uint8_t>& chkBytes,
                      const std::vector<MpqExtraFile>& extraFiles) {
    // 1) 파일 인덱스를 정의: 0 = scenario.chk, 1.. = extraFiles
    const size_t fileCount = 1 + extraFiles.size();

    // 2) hashTable 크기 결정 (2의 제곱, 최소 16, 부하 50% 이하)
    uint32_t hashTableSize = roundUpPow2(static_cast<uint32_t>(fileCount * 2));
    if (hashTableSize < 16) hashTableSize = 16;

    // 3) 각 파일 압축 후 블록 데이터 준비
    std::vector<std::vector<uint8_t>> blockPayloads(fileCount);
    std::vector<uint32_t> blockFileSizes(fileCount);
    std::vector<uint32_t> blockFlags(fileCount);

    // 3-a) scenario.chk
    {
        std::string raw(chkBytes.begin(), chkBytes.end());
        std::string compressed = compressToBlock(raw, MAFA_COMPRESS_STANDARD,
                                                 MAFA_COMPRESS_STANDARD);
        blockPayloads[0].assign(compressed.begin(), compressed.end());
        blockFileSizes[0] = static_cast<uint32_t>(raw.size());
        // MPQ_FILE_EXISTS (0x80000000) | BLOCK_COMPRESSED. 무암호화.
        blockFlags[0] = 0x80000000u | BLOCK_COMPRESSED;
    }

    // 3-b) extraFiles — 무압축으로 저장 (안전성 우선)
    for (size_t i = 0; i < extraFiles.size(); ++i) {
        size_t idx = 1 + i;
        const auto& f = extraFiles[i];
        blockPayloads[idx].assign(f.data.begin(), f.data.end());
        blockFileSizes[idx] = static_cast<uint32_t>(f.data.size());
        blockFlags[idx] = 0x80000000u;  // Exists, 무압축, 무암호화
    }

    // 4) 레이아웃 결정: header(32) → blocks → hashTable → blockTable
    size_t cursor = sizeof(MPQHeader);
    std::vector<uint32_t> blockOffsets(fileCount);
    std::vector<uint32_t> blockSizes(fileCount);
    for (size_t i = 0; i < fileCount; ++i) {
        blockOffsets[i] = static_cast<uint32_t>(cursor);
        blockSizes[i] = static_cast<uint32_t>(blockPayloads[i].size());
        cursor += blockPayloads[i].size();
    }
    uint32_t hashTableOffset = static_cast<uint32_t>(cursor);
    cursor += hashTableSize * sizeof(HashTableEntry);
    uint32_t blockTableOffset = static_cast<uint32_t>(cursor);
    cursor += fileCount * sizeof(BlockTableEntry);
    size_t archiveSize = cursor;

    // 5) 버퍼 할당 + 헤더 작성
    std::vector<uint8_t> buf(archiveSize, 0);

    MPQHeader header{};
    header.magic = 0x1A51504D;  // "MPQ\x1A"
    header.headerSize = sizeof(MPQHeader);
    header.mpqSize = static_cast<uint32_t>(archiveSize);
    header.mpqVersion = 0;
    header.sectorSizeShift = 3;
    header.unused0 = 0;
    header.hashTableOffset = hashTableOffset;
    header.blockTableOffset = blockTableOffset;
    header.hashTableEntryCount = hashTableSize;
    header.blockTableEntryCount = static_cast<uint32_t>(fileCount);
    std::memcpy(buf.data(), &header, sizeof(header));

    // 6) 블록 페이로드 복사
    for (size_t i = 0; i < fileCount; ++i) {
        std::memcpy(buf.data() + blockOffsets[i], blockPayloads[i].data(),
                    blockPayloads[i].size());
    }

    // 7) 해시 테이블 작성 (전부 빈 슬롯으로 초기화 후 정해진 위치에 엔트리 박기)
    std::vector<HashTableEntry> hashTable(hashTableSize);
    for (auto& h : hashTable) {
        h.hashA = 0xFFFFFFFFu;
        h.hashB = 0xFFFFFFFFu;
        h.language = 0;
        h.platform = 0;
        h.unused0 = 0;
        h.blockIndex = 0xFFFFFFFFu;
    }

    auto placeEntry = [&](const std::string& fname, uint32_t blockIndex) {
        uint32_t hashKey = HashString(fname.c_str(), MPQ_HASH_TABLE_OFFSET);
        uint32_t startIdx = hashKey & (hashTableSize - 1);
        uint32_t idx = startIdx;
        do {
            if (hashTable[idx].blockIndex == 0xFFFFFFFFu) {
                writeFreshHashEntry(hashTable[idx], fname, 0, 0, blockIndex);
                return true;
            }
            idx = (idx + 1) & (hashTableSize - 1);
        } while (idx != startIdx);
        return false;
    };

    if (!placeEntry("staredit\\scenario.chk", 0)) {
        throw std::runtime_error("Hash table too small for scenario.chk");
    }
    for (size_t i = 0; i < extraFiles.size(); ++i) {
        if (!placeEntry(extraFiles[i].name, static_cast<uint32_t>(1 + i))) {
            // 한 두 개 못 박혀도 (listfile)/(attributes) 같은 부가물이라 계속 진행
        }
    }

    // 8) hashTable / blockTable 직렬화 → 암호화 → 버퍼에 복사
    std::vector<uint8_t> hashBuf(hashTableSize * sizeof(HashTableEntry));
    std::memcpy(hashBuf.data(), hashTable.data(), hashBuf.size());
    uint32_t hashTableKey = HashString("(hash table)", MPQ_HASH_FILE_KEY);
    EncryptData(hashBuf.data(), static_cast<uint32_t>(hashBuf.size()), hashTableKey);
    std::memcpy(buf.data() + hashTableOffset, hashBuf.data(), hashBuf.size());

    std::vector<BlockTableEntry> blockTable(fileCount);
    for (size_t i = 0; i < fileCount; ++i) {
        blockTable[i].blockOffset = blockOffsets[i];
        blockTable[i].blockSize = blockSizes[i];
        blockTable[i].fileSize = blockFileSizes[i];
        blockTable[i].fileFlag = blockFlags[i];
    }
    std::vector<uint8_t> blockBuf(fileCount * sizeof(BlockTableEntry));
    std::memcpy(blockBuf.data(), blockTable.data(), blockBuf.size());
    uint32_t blockTableKey = HashString("(block table)", MPQ_HASH_FILE_KEY);
    EncryptData(blockBuf.data(), static_cast<uint32_t>(blockBuf.size()), blockTableKey);
    std::memcpy(buf.data() + blockTableOffset, blockBuf.data(), blockBuf.size());

    // 9) 파일에 쓰기
    std::remove(path.c_str());
    std::ofstream os(path, std::ios_base::binary);
    if (!os.is_open()) {
        throw std::runtime_error("Failed to open output: " + path);
    }
    os.write(reinterpret_cast<const char*>(buf.data()), buf.size());
    if (!os.good()) {
        throw std::runtime_error("Failed to write output: " + path);
    }
}

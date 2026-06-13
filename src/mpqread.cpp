#include "mpqread.h"

#include <iostream>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "cmpdcmp.h"
#include "debug_log.h"
#include "mpqcrypt.h"
#include "mpqtypes.h"

class MpqReadImpl {
public:
    MpqReadImpl(const std::string& mpqName, bool useFreezeTrick);
    ~MpqReadImpl();

    int getHashEntryCount() const;
    const HashTableEntry* getHashEntry(int index) const;
    const HashTableEntry* getHashEntryByName(const std::string& fname) const;
    const BlockTableEntry* getBlockEntry(int index) const;
    std::string getDecryptedBlockContent(const HashTableEntry* hte,
                                         const BlockTableEntry* blockEntry) const;
    bool isFreezeMode() const { return useFreezeTrick_; }
    const MPQHeader& header() const { return header_; }

private:
    uint32_t getKnownFilenameKey(const HashTableEntry* hashEntry,
                                 const BlockTableEntry* blockEntry) const;

    MPQHeader header_;
    bool useFreezeTrick_;
    mutable std::set<std::string> knownFileNames_;
    std::vector<HashTableEntry> hashTable_;
    std::vector<BlockTableEntry> blockTable_;
    size_t startBlockOffset_;
    size_t realBlockCount_;
    mutable std::ifstream is_;
};

namespace {

template <typename T>
void readTable(std::istream& is, size_t tableOffset, size_t entryCount,
               const char* tableKeyString, std::vector<T>& output) {
    size_t tableSize = entryCount * sizeof(T);
    std::vector<char> tableData(tableSize);
    is.seekg(tableOffset, std::ios_base::beg);
    is.read(tableData.data(), tableSize);

    uint32_t hashTableKey = HashString(tableKeyString, MPQ_HASH_FILE_KEY);
    DecryptData(tableData.data(), tableSize, hashTableKey);

    for (size_t i = 0; i < tableSize / sizeof(T); ++i) {
        const auto& entry = *(reinterpret_cast<T*>(tableData.data()) + i);
        output.push_back(entry);
    }
}

}  // namespace

MpqReadImpl::MpqReadImpl(const std::string& mpqName, bool useFreezeTrick)
    : useFreezeTrick_(useFreezeTrick) {
    try {
        is_.exceptions(std::ifstream::failbit | std::ifstream::badbit);
        is_.open(mpqName, std::ios_base::in | std::ios_base::binary);
        is_.read(reinterpret_cast<char*>(&header_), sizeof(header_));

        // 일반 보호 분기에서도 sectorSizeShift != 3 인 경우가 있어 신호만 흘림.
        // (이전 cpp는 throw 했지만 새 도구는 관용적으로 처리)

        readTable<HashTableEntry>(is_, header_.hashTableOffset,
                                  header_.hashTableEntryCount,
                                  "(hash table)", hashTable_);

        if (useFreezeTrick_) {
            // freeze: block table은 offset=0, count는 (헤더값 - 2)
            uint32_t freezeBlockCount =
                header_.blockTableEntryCount >= 2 ? header_.blockTableEntryCount - 2 : 0;
            readTable<BlockTableEntry>(is_, 0, freezeBlockCount,
                                       "(block table)", blockTable_);
            startBlockOffset_ =
                (header_.hashTableOffset +
                 header_.hashTableEntryCount * sizeof(HashTableEntry) + 0xF) &
                ~static_cast<size_t>(0xF);
            realBlockCount_ =
                blockTable_.size() > startBlockOffset_ / sizeof(BlockTableEntry)
                    ? blockTable_.size() - startBlockOffset_ / sizeof(BlockTableEntry)
                    : 0;
        } else {
            readTable<BlockTableEntry>(is_, header_.blockTableOffset,
                                       header_.blockTableEntryCount,
                                       "(block table)", blockTable_);
            startBlockOffset_ = sizeof(MPQHeader);
            realBlockCount_ = blockTable_.size();
        }
    } catch (const std::ifstream::failure& e) {
        throw std::runtime_error(std::string("Error reading file: ") + e.what());
    }
}

MpqReadImpl::~MpqReadImpl() {
    if (is_.is_open()) is_.close();
}

int MpqReadImpl::getHashEntryCount() const {
    return static_cast<int>(hashTable_.size());
}

const HashTableEntry* MpqReadImpl::getHashEntry(int index) const {
    if (index < 0 || static_cast<size_t>(index) >= hashTable_.size()) return nullptr;
    return &hashTable_[index];
}

const HashTableEntry* MpqReadImpl::getHashEntryByName(const std::string& fname) const {
    if (hashTable_.empty()) return nullptr;
    const char* cstr = fname.c_str();
    uint32_t hashA = HashString(cstr, MPQ_HASH_NAME_A);
    uint32_t hashB = HashString(cstr, MPQ_HASH_NAME_B);
    uint32_t hashKey = HashString(cstr, MPQ_HASH_TABLE_OFFSET);
    size_t startIndex = hashKey & (hashTable_.size() - 1);
    size_t index = startIndex;
    do {
        const HashTableEntry* entry = &hashTable_[index];
        if (entry->blockIndex == 0xFFFFFFFF) return nullptr;
        if (entry->hashA == hashA && entry->hashB == hashB) {
            knownFileNames_.insert(fname);
            return entry;
        }
        index = (index + 1) & (hashTable_.size() - 1);
    } while (index != startIndex);
    return nullptr;
}

const BlockTableEntry* MpqReadImpl::getBlockEntry(int index) const {
    if (index < 0 || static_cast<size_t>(index) >= blockTable_.size()) return nullptr;
    return &blockTable_[index];
}

uint32_t MpqReadImpl::getKnownFilenameKey(const HashTableEntry* hashEntry,
                                          const BlockTableEntry* blockEntry) const {
    uint32_t fileKey = 0xFFFFFFFF;
    for (const auto& s : knownFileNames_) {
        uint32_t expectedHashA = HashString(s.c_str(), MPQ_HASH_NAME_A);
        uint32_t expectedHashB = HashString(s.c_str(), MPQ_HASH_NAME_B);
        if (expectedHashA == hashEntry->hashA && expectedHashB == hashEntry->hashB) {
            fileKey = HashString(s.c_str(), MPQ_HASH_FILE_KEY);
            if (blockEntry->fileFlag & BLOCK_KEY_ADJUSTED) {
                fileKey = (fileKey + blockEntry->blockOffset) ^ blockEntry->fileSize;
            }
            break;
        }
    }
    return fileKey;
}

std::string MpqReadImpl::getDecryptedBlockContent(
    const HashTableEntry* hashEntry, const BlockTableEntry* blockEntry) const {
    bool compressed = (blockEntry->fileFlag & BLOCK_COMPRESSED) != 0;
    bool encrypted = (blockEntry->fileFlag & BLOCK_ENCRYPTED) != 0;
    bool imploded = (blockEntry->fileFlag & BLOCK_IMPLODED) != 0;

    if (useFreezeTrick_) {
        size_t blockStartIndex = startBlockOffset_ / sizeof(BlockTableEntry);
        size_t hashBlockIndex = hashEntry->blockIndex;
        size_t maxBlockIndex = header_.blockTableEntryCount >= 2
                                   ? header_.blockTableEntryCount - 2
                                   : 0;
        if (hashBlockIndex < blockStartIndex || hashBlockIndex >= maxBlockIndex) {
            return std::string();
        }
    }

    is_.seekg(blockEntry->blockOffset, std::ios_base::beg);
    std::vector<char> buf(blockEntry->blockSize);
    is_.read(buf.data(), blockEntry->blockSize);

    if (encrypted) {
        const size_t sectorSize = 512u << header_.sectorSizeShift;
        size_t sectorNum = (blockEntry->fileSize + sectorSize - 1) / sectorSize;
        uint32_t fileKey = getKnownFilenameKey(hashEntry, blockEntry);

        if (compressed || imploded) {
            if (fileKey == 0xFFFFFFFF) {
                const auto* encryptedOffsetTable =
                    reinterpret_cast<const uint32_t*>(buf.data());
                const uint32_t offsetTableLength =
                    static_cast<uint32_t>(4 * (sectorNum + 1));
                fileKey = GetFileDecryptKey(
                    encryptedOffsetTable, offsetTableLength, offsetTableLength,
                    [&](const void* _decrypted) {
                        const auto* tbl = static_cast<const uint32_t*>(_decrypted);
                        if (tbl[0] != offsetTableLength) return false;
                        if (tbl[sectorNum] != blockEntry->blockSize) return false;
                        for (size_t i = 0; i < sectorNum; ++i) {
                            if (tbl[i] > tbl[i + 1]) return false;
                        }
                        return true;
                    });
                if (fileKey == 0xFFFFFFFF) return std::string();
                fileKey++;
            }
            DecryptData(buf.data(), 4 * (sectorNum + 1), fileKey - 1);
            auto* sectorOffsetTable = reinterpret_cast<uint32_t*>(buf.data());
            for (size_t i = 0; i < sectorNum; ++i) {
                size_t off = sectorOffsetTable[i];
                size_t sz = sectorOffsetTable[i + 1] - sectorOffsetTable[i];
                DecryptData(buf.data() + off, sz, fileKey + i);
            }
        } else {
            if (fileKey == 0xFFFFFFFF) return std::string();
            for (size_t i = 0; i < sectorNum; ++i) {
                size_t off = sectorSize * i;
                size_t sz = std::min<size_t>(sectorSize, blockEntry->fileSize - off);
                DecryptData(buf.data() + off, sz, fileKey + i);
            }
        }
    }

    return std::string(buf.begin(), buf.end());
}

// ---------------- MpqRead (public wrapper) ----------------

MpqRead::MpqRead(const std::string& mpqName, bool useFreezeTrick)
    : pimpl(new MpqReadImpl(mpqName, useFreezeTrick)) {}

MpqRead::~MpqRead() = default;

int MpqRead::getHashEntryCount() const { return pimpl->getHashEntryCount(); }

const HashTableEntry* MpqRead::getHashEntry(int index) const {
    return pimpl->getHashEntry(index);
}

const HashTableEntry* MpqRead::getHashEntryByName(const std::string& fname) const {
    return pimpl->getHashEntryByName(fname);
}

const BlockTableEntry* MpqRead::getBlockEntry(int index) const {
    return pimpl->getBlockEntry(index);
}

std::string MpqRead::getBlockContent(const HashTableEntry* hashEntry) const {
    auto blockEntry = pimpl->getBlockEntry(hashEntry->blockIndex);
    if (!blockEntry) return std::string();
    return pimpl->getDecryptedBlockContent(hashEntry, blockEntry);
}

std::vector<uint8_t> MpqRead::getScenarioChkBytes() const {
    if (g_melterVerbose) std::cerr << "  [chk] looking up scenario.chk\n";
    const HashTableEntry* entry =
        pimpl->getHashEntryByName("staredit\\scenario.chk");
    if (!entry) {
        for (int i = 0; i < pimpl->getHashEntryCount(); ++i) {
            const HashTableEntry* h = pimpl->getHashEntry(i);
            if (h && h->hashA == kScenarioChkHashA && h->hashB == kScenarioChkHashB &&
                h->blockIndex < 0xFFFFFFFEu) {
                entry = h;
                break;
            }
        }
    }
    if (!entry) { if (g_melterVerbose) std::cerr << "  [chk] no hash entry\n"; return {}; }
    if (g_melterVerbose) std::cerr << "  [chk] blockIndex=" << entry->blockIndex << "\n";

    const BlockTableEntry* block = pimpl->getBlockEntry(entry->blockIndex);
    if (!block) { if (g_melterVerbose) std::cerr << "  [chk] no block entry\n"; return {}; }
    if (g_melterVerbose) std::cerr << "  [chk] block: off=0x" << std::hex << block->blockOffset
              << " csize=" << std::dec << block->blockSize
              << " fsize=" << block->fileSize
              << " flags=0x" << std::hex << block->fileFlag << std::dec << "\n";

    std::string raw = pimpl->getDecryptedBlockContent(entry, block);
    if (g_melterVerbose) std::cerr << "  [chk] raw block size: " << raw.size() << "\n";
    if (raw.empty()) return {};

    try {
        if (block->fileFlag & BLOCK_COMPRESSED) {
            if (g_melterVerbose) std::cerr << "  [chk] decompressing (fileSize=" << block->fileSize << ")\n";
            std::string out = decompressBlock(block->fileSize, raw);
            if (g_melterVerbose) std::cerr << "  [chk] decompressed: " << out.size() << " bytes\n";
            return std::vector<uint8_t>(out.begin(), out.end());
        } else {
            return std::vector<uint8_t>(raw.begin(), raw.end());
        }
    } catch (const std::exception& e) {
        if (g_melterVerbose) std::cerr << "  [chk] decompress threw: " << e.what() << "\n";
        return {};
    }
}

std::vector<HashTableEntry> MpqRead::getHashTable() const {
    std::vector<HashTableEntry> out;
    int n = pimpl->getHashEntryCount();
    out.reserve(n);
    for (int i = 0; i < n; ++i) {
        const HashTableEntry* h = pimpl->getHashEntry(i);
        if (h) out.push_back(*h);
    }
    return out;
}

std::vector<BlockTableEntry> MpqRead::getBlockTable() const {
    std::vector<BlockTableEntry> out;
    // BlockTable size 는 MpqReadImpl 에 직접 노출 없으므로 hash entry 들의 blockIndex 최댓값 찾기 + 알려진 freeze 값.
    // 가장 안전: 헤더에서 읽은 blockTableEntryCount 만큼 시도.
    // pimpl->getBlockEntry(i) 가 nullptr 반환할 때까지 iterate.
    int i = 0;
    while (true) {
        const BlockTableEntry* b = pimpl->getBlockEntry(i);
        if (!b) break;
        out.push_back(*b);
        ++i;
        if (i > 200000) break;  // safety cap
    }
    return out;
}

std::vector<uint8_t> MpqRead::getRawHeader() const {
    // keycalc 의 getMapHandleEPD bootstrap 이 읽는 필드:
    //   +0x10 hashTableOffset, +0x18 hashTableEntryCount, +0x1C blockTableEntryCount
    //   (+0x0C 의 sectorSizeShift 도 sector layout 에 쓰임).
    // 파싱된 header_ 를 그대로 32바이트로 직렬화해 노출한다 (#pragma pack(1) 이므로
    // 메모리 레이아웃이 disk MPQ 헤더와 1:1).  freeze trick 으로 blockTableEntryCount
    // 를 (headerval-2) 로 조정하지 *않은* 원본 헤더 값을 그대로 돌려준다 — keycalc 는
    // 원본 blockTableEntryCount (= disk +0x1C, 본 맵에서 0x7C70=31856) 를 기대한다.
    const MPQHeader& h = pimpl->header();
    std::vector<uint8_t> out(sizeof(MPQHeader));
    std::memcpy(out.data(), &h, sizeof(MPQHeader));
    return out;
}

std::vector<uint8_t> MpqRead::readFile(const std::string& fname) const {
    const HashTableEntry* entry = pimpl->getHashEntryByName(fname);
    if (!entry) return std::vector<uint8_t>();

    const BlockTableEntry* block = pimpl->getBlockEntry(entry->blockIndex);
    if (!block) return std::vector<uint8_t>();

    std::string raw = pimpl->getDecryptedBlockContent(entry, block);
    if (raw.empty()) return std::vector<uint8_t>();

    try {
        if (block->fileFlag & BLOCK_COMPRESSED) {
            std::string out = decompressBlock(block->fileSize, raw);
            return std::vector<uint8_t>(out.begin(), out.end());
        }
        return std::vector<uint8_t>(raw.begin(), raw.end());
    } catch (const std::runtime_error&) {
        return std::vector<uint8_t>();
    }
}

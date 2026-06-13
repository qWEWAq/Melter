#include "vmemory.h"

#include <cstdio>
#include <iostream>
#include <sstream>

VMemory::VMemory() = default;
VMemory::~VMemory() = default;

void VMemory::recordDrop(uint32_t address, uint32_t value, uint8_t width, bool unmapped) {
    droppedWriteEvents_++;
    auto& d = droppedWrites_[address];
    d.count++;
    d.lastValue = value;
    d.width = width;
    d.unmapped = unmapped;
}

void VMemory::allocAt(uint32_t address, uint32_t size, const std::string& label) {
    if (size == 0) return;

    // 겹침 검사: [address, address+size) 가 기존 블록과 만나는지.
    // 1) address 가 어떤 블록 안에 있는지 확인
    auto it = findContaining(address);
    if (it != blocks_.end()) {
        std::ostringstream oss;
        oss << "allocAt overlap: 0x" << std::hex << address << " + " << std::dec << size
            << " overlaps existing block 0x" << std::hex << it->second.start
            << " size " << std::dec << it->second.size;
        throw std::runtime_error(oss.str());
    }
    // 2) [address, address+size) 안에 다른 블록의 start 가 있는지
    auto next = blocks_.lower_bound(address);
    if (next != blocks_.end() && next->first < address + size) {
        std::ostringstream oss;
        oss << "allocAt overlap: 0x" << std::hex << address << " + " << std::dec << size
            << " contains existing block 0x" << std::hex << next->first;
        throw std::runtime_error(oss.str());
    }

    Block b;
    b.start = address;
    b.size = size;
    b.data.assign(size, 0);
    b.label = label;
    blocks_.emplace(address, std::move(b));
}

void VMemory::allocAt(uint32_t address, const std::vector<uint8_t>& data, const std::string& label) {
    allocAt(address, static_cast<uint32_t>(data.size()), label);
    if (!data.empty()) {
        auto it = blocks_.find(address);
        std::memcpy(it->second.data.data(), data.data(), data.size());
    }
}

void VMemory::deallocRange(uint32_t address, uint32_t size) {
    uint32_t endAddr = address + size;
    auto it = blocks_.begin();
    while (it != blocks_.end()) {
        uint32_t bStart = it->first;
        uint32_t bEnd = bStart + it->second.size;
        if (bEnd > address && bStart < endAddr) {
            it = blocks_.erase(it);
        } else {
            ++it;
        }
    }
}

uint32_t VMemory::allocDynamic(uint32_t size, uint32_t startRange, uint32_t endRange,
                               const std::string& label) {
    if (size == 0 || startRange >= endRange || (endRange - startRange) < size) {
        throw std::runtime_error("allocDynamic: invalid range or size");
    }

    // 정렬: 4바이트 경계로 시작 주소 정렬.
    auto align4 = [](uint32_t v) { return (v + 3) & ~3u; };

    uint32_t cursor = align4(startRange);
    // 블록 순회하며 빈 구간 찾기.
    auto it = blocks_.lower_bound(cursor);
    while (cursor + size <= endRange) {
        uint32_t blockStart = (it != blocks_.end()) ? it->first : endRange;
        if (cursor + size <= blockStart) {
            // 여기에 할당 가능
            allocAt(cursor, size, label);
            return cursor;
        }
        // 이 블록을 건너뛰어 다음 가능 위치로
        cursor = align4(it->second.start + it->second.size);
        ++it;
    }
    throw std::runtime_error("allocDynamic: no space available in range");
}

std::map<uint32_t, VMemory::Block>::iterator VMemory::findContaining(uint32_t address) {
    if (blocks_.empty()) return blocks_.end();
    // upper_bound: address 보다 큰 첫 키. 그 직전이 contains 후보.
    auto it = blocks_.upper_bound(address);
    if (it == blocks_.begin()) return blocks_.end();
    --it;
    if (address >= it->first && address < it->first + it->second.size) return it;
    return blocks_.end();
}

std::map<uint32_t, VMemory::Block>::const_iterator VMemory::findContaining(uint32_t address) const {
    if (blocks_.empty()) return blocks_.end();
    auto it = blocks_.upper_bound(address);
    if (it == blocks_.begin()) return blocks_.end();
    --it;
    if (address >= it->first && address < it->first + it->second.size) return it;
    return blocks_.end();
}

VMemory::Block* VMemory::findBlock(uint32_t address) {
    auto it = findContaining(address);
    return it == blocks_.end() ? nullptr : &it->second;
}

const VMemory::Block* VMemory::findBlock(uint32_t address) const {
    auto it = findContaining(address);
    return it == blocks_.end() ? nullptr : &it->second;
}

VMemory::Block& VMemory::requireRange(uint32_t address, uint32_t size) {
    auto it = findContaining(address);
    if (it == blocks_.end() ||
        address + size > it->first + it->second.size) {
        std::ostringstream oss;
        oss << "VMemory access out of range: 0x" << std::hex << address
            << " + " << std::dec << size;
        throw std::runtime_error(oss.str());
    }
    return it->second;
}

const VMemory::Block& VMemory::requireRange(uint32_t address, uint32_t size) const {
    auto it = findContaining(address);
    if (it == blocks_.end() ||
        address + size > it->first + it->second.size) {
        std::ostringstream oss;
        oss << "VMemory access out of range: 0x" << std::hex << address
            << " + " << std::dec << size;
        throw std::runtime_error(oss.str());
    }
    return it->second;
}

void VMemory::writeU8(uint32_t address, uint8_t value) {
    if (lenient_) {
        auto it = findContaining(address);
        if (it == blocks_.end()) { if (trackDropped_) recordDrop(address, value, 1, true); return; }
        it->second.data[address - it->first] = value;
        return;
    }
    Block& b = requireRange(address, 1);
    b.data[address - b.start] = value;
}

void VMemory::writeU16(uint32_t address, uint16_t value) {
    if (lenient_) {
        auto it = findContaining(address);
        if (it == blocks_.end()) { if (trackDropped_) recordDrop(address, value, 2, true); return; }
        if (address + 2 > it->first + it->second.size) { if (trackDropped_) recordDrop(address, value, 2, false); return; }
        Block& b = it->second;
        uint32_t off = address - b.start;
        b.data[off] = value & 0xFF;
        b.data[off + 1] = (value >> 8) & 0xFF;
        return;
    }
    Block& b = requireRange(address, 2);
    uint32_t off = address - b.start;
    b.data[off] = value & 0xFF;
    b.data[off + 1] = (value >> 8) & 0xFF;
}

void VMemory::writeU32(uint32_t address, uint32_t value) {
    if (trackWrites_) writeCounts_[address]++;

    // history 추적 (필터된 주소만)
    if (trackHistory_) {
        bool wantTrack = historyFilter_.empty() || historyFilter_.count(address);
        if (wantTrack) {
            // prev 값 읽기 (lenient 모드 가정)
            uint32_t prev = 0;
            auto it = findContaining(address);
            if (it != blocks_.end() && address + 4 <= it->first + it->second.size) {
                const Block& bb = it->second;
                uint32_t o = address - bb.start;
                prev = uint32_t(bb.data[o]) |
                       (uint32_t(bb.data[o + 1]) << 8) |
                       (uint32_t(bb.data[o + 2]) << 16) |
                       (uint32_t(bb.data[o + 3]) << 24);
            }
            if (prev != value) {
                history_.push_back({address, prev, value, writeSeq_++});
            }
        }
    }

    if (lenient_) {
        auto it = findContaining(address);
        if (it == blocks_.end()) { if (trackDropped_) recordDrop(address, value, 4, true); return; }
        if (address + 4 > it->first + it->second.size) { if (trackDropped_) recordDrop(address, value, 4, false); return; }
        Block& b = it->second;
        uint32_t off = address - b.start;
        b.data[off + 0] = value & 0xFF;
        b.data[off + 1] = (value >> 8) & 0xFF;
        b.data[off + 2] = (value >> 16) & 0xFF;
        b.data[off + 3] = (value >> 24) & 0xFF;
        return;
    }
    Block& b = requireRange(address, 4);
    uint32_t off = address - b.start;
    b.data[off + 0] = value & 0xFF;
    b.data[off + 1] = (value >> 8) & 0xFF;
    b.data[off + 2] = (value >> 16) & 0xFF;
    b.data[off + 3] = (value >> 24) & 0xFF;
}

void VMemory::writeBytes(uint32_t address, const uint8_t* data, uint32_t size) {
    if (size == 0) return;
    if (lenient_) {
        auto it = findContaining(address);
        if (it == blocks_.end()) { if (trackDropped_) recordDrop(address, size, 0, true); return; }
        if (address + size > it->first + it->second.size) {
            // FIX: range crosses a block boundary. SC memory is contiguous across adjacent
            // allocations (e.g. BwUpgradesAvailable + BwUpgradesResearched are one logical region
            // that freeze's RestorePUPx copies as 360 bytes). Previously this whole write was
            // SILENTLY DROPPED, which broke pts_runner's snapshot/restore of the obfuData source
            // tables for the 8-player run. Fall back to per-byte writes so the write lands in
            // whichever (adjacent) blocks contain each byte.
            for (uint32_t i = 0; i < size; ++i) {
                auto bit = findContaining(address + i);
                if (bit == blocks_.end()) { if (trackDropped_) recordDrop(address + i, data[i], 1, true); continue; }
                bit->second.data[(address + i) - bit->second.start] = data[i];
            }
            return;
        }
        Block& b = it->second;
        std::memcpy(b.data.data() + (address - b.start), data, size);
        return;
    }
    Block& b = requireRange(address, size);
    std::memcpy(b.data.data() + (address - b.start), data, size);
}

void VMemory::writeBytes(uint32_t address, const std::vector<uint8_t>& data) {
    writeBytes(address, data.data(), static_cast<uint32_t>(data.size()));
}

uint8_t VMemory::readU8(uint32_t address) const {
    if (lenient_) {
        auto it = findContaining(address);
        if (it == blocks_.end()) return 0;
        return it->second.data[address - it->first];
    }
    const Block& b = requireRange(address, 1);
    return b.data[address - b.start];
}

uint16_t VMemory::readU16(uint32_t address) const {
    if (lenient_) {
        auto it = findContaining(address);
        if (it == blocks_.end()) return 0;
        if (address + 2 > it->first + it->second.size) return 0;
        const Block& b = it->second;
        uint32_t off = address - b.start;
        return uint16_t(b.data[off]) | (uint16_t(b.data[off + 1]) << 8);
    }
    const Block& b = requireRange(address, 2);
    uint32_t off = address - b.start;
    return uint16_t(b.data[off]) | (uint16_t(b.data[off + 1]) << 8);
}

uint32_t VMemory::readU32(uint32_t address) const {
    if (lenient_) {
        auto it = findContaining(address);
        if (it == blocks_.end()) return 0;
        if (address + 4 > it->first + it->second.size) return 0;
        const Block& b = it->second;
        uint32_t off = address - b.start;
        return uint32_t(b.data[off]) |
               (uint32_t(b.data[off + 1]) << 8) |
               (uint32_t(b.data[off + 2]) << 16) |
               (uint32_t(b.data[off + 3]) << 24);
    }
    const Block& b = requireRange(address, 4);
    uint32_t off = address - b.start;
    return uint32_t(b.data[off]) |
           (uint32_t(b.data[off + 1]) << 8) |
           (uint32_t(b.data[off + 2]) << 16) |
           (uint32_t(b.data[off + 3]) << 24);
}

std::vector<uint8_t> VMemory::readBytes(uint32_t address, uint32_t size) const {
    if (size == 0) return {};
    if (lenient_) {
        auto it = findContaining(address);
        if (it == blocks_.end()) return std::vector<uint8_t>(size, 0);
        if (address + size > it->first + it->second.size) {
            // FIX: range crosses a block boundary — previously returned ALL ZEROS, which made
            // pts_runner's obfuData-source snapshot a zero buffer. Fall back to per-byte reads so
            // the read spans adjacent (contiguous) blocks; unmapped bytes read as 0 (SC NULL page).
            std::vector<uint8_t> out(size, 0);
            for (uint32_t i = 0; i < size; ++i) {
                auto bit = findContaining(address + i);
                if (bit != blocks_.end()) out[i] = bit->second.data[(address + i) - bit->second.start];
            }
            return out;
        }
        const Block& b = it->second;
        const uint8_t* p = b.data.data() + (address - b.start);
        return std::vector<uint8_t>(p, p + size);
    }
    const Block& b = requireRange(address, size);
    const uint8_t* p = b.data.data() + (address - b.start);
    return std::vector<uint8_t>(p, p + size);
}

size_t VMemory::totalBytes() const {
    size_t n = 0;
    for (const auto& kv : blocks_) n += kv.second.size;
    return n;
}

void VMemory::dumpBlocks() const {
    std::cerr << "[VMemory] " << blocks_.size() << " blocks, "
              << totalBytes() << " total bytes\n";
    for (const auto& kv : blocks_) {
        std::fprintf(stderr, "  0x%08X - 0x%08X (%u bytes) %s\n",
                     kv.second.start,
                     kv.second.start + kv.second.size,
                     kv.second.size,
                     kv.second.label.c_str());
    }
}

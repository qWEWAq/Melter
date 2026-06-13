#ifndef SECTION_H
#define SECTION_H

#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <sstream>

struct Section {
    char name[5];             // 4-byte name
    uint32_t size;            // 4-byte section size
    std::vector<uint8_t> data; // Section data

    Section(const char* n, uint32_t s, const std::vector<uint8_t>& d);
};

struct STRxSection {
    char typeName[4];
    uint32_t sectionLength;
    uint32_t strLength;
    std::vector<uint32_t> strLocation;
    std::vector<std::string> strData;
};

#endif
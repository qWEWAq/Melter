#include "file_io.h"

#include <cstdio>
#include <fstream>

#ifdef _WIN32
#include <direct.h>
#define PATH_SEP '\\'
#else
#include <sys/stat.h>
#include <sys/types.h>
#define PATH_SEP '/'
#endif

std::vector<uint8_t> readAllBytes(const std::string& path) {
    std::ifstream is(path, std::ios::binary | std::ios::ate);
    if (!is.is_open()) return {};
    std::streamsize size = is.tellg();
    if (size <= 0) return {};
    is.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(static_cast<size_t>(size));
    if (!is.read(reinterpret_cast<char*>(buf.data()), size)) return {};
    return buf;
}

void ensureDirectory(const std::string& path) {
    if (path.empty()) return;
#ifdef _WIN32
    _mkdir(path.c_str());
#else
    mkdir(path.c_str(), 0755);
#endif
}

std::string parentDirectory(const std::string& path) {
    size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos) return "";
    return path.substr(0, pos);
}

std::string fileExtension(const std::string& path) {
    size_t slash = path.find_last_of("/\\");
    size_t dot = path.find_last_of('.');
    if (dot == std::string::npos) return "";
    if (slash != std::string::npos && dot < slash) return "";
    return path.substr(dot);
}

std::string fileBaseName(const std::string& path) {
    size_t slash = path.find_last_of("/\\");
    size_t start = (slash == std::string::npos) ? 0 : slash + 1;
    size_t dot = path.find_last_of('.');
    if (dot == std::string::npos || dot < start) {
        return path.substr(start);
    }
    return path.substr(start, dot - start);
}

std::string joinPath(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    char last = a[a.size() - 1];
    if (last == '/' || last == '\\') return a + b;
    return a + PATH_SEP + b;
}

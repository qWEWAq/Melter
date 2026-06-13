#ifndef CHKREPAIR_FILE_IO_H
#define CHKREPAIR_FILE_IO_H

#include <cstdint>
#include <string>
#include <vector>

// 파일 전체를 바이트로 읽기. 실패시 빈 벡터.
std::vector<uint8_t> readAllBytes(const std::string& path);

// 디렉터리가 없으면 생성 (단일 레벨). 이미 있으면 무동작.
void ensureDirectory(const std::string& path);

// 파일 경로의 부모 디렉터리 경로.
std::string parentDirectory(const std::string& path);

// 파일 경로의 확장자 (점 포함). 없으면 빈 문자열.
std::string fileExtension(const std::string& path);

// 파일 경로의 베이스 이름 (디렉터리 제외, 확장자 제외).
std::string fileBaseName(const std::string& path);

// 두 경로 결합 (호스트 OS 구분자 적용).
std::string joinPath(const std::string& a, const std::string& b);

#endif  // CHKREPAIR_FILE_IO_H

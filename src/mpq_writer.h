#ifndef CHKREPAIR_MPQ_WRITER_H
#define CHKREPAIR_MPQ_WRITER_H

#include <cstdint>
#include <string>
#include <vector>

struct MpqExtraFile {
    std::string name;
    std::vector<uint8_t> data;
};

// scratch에서 표준 MPQ 아카이브를 만들어 path에 쓴다.
// scenario.chk가 첫 파일이 되고, extraFiles는 그 뒤에 무압축으로 추가된다.
//
// hashTableSize는 2의 제곱수. extraFiles 수에 맞춰 자동 결정.
// 출력 디렉터리가 없으면 만든다.
void writeStandardMpq(const std::string& path,
                      const std::vector<uint8_t>& chkBytes,
                      const std::vector<MpqExtraFile>& extraFiles);

#endif  // CHKREPAIR_MPQ_WRITER_H

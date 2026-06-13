// Minimal zlib stub for melter (Windows build).
// 실제 zlib 가 필요한 .scx 는 거의 없음 (PKWare implode 0x08 이 표준).
// 진짜 zlib 가 필요해지면 vcpkg install zlib 으로 교체.

#ifndef MELTER_ZLIB_STUB_H
#define MELTER_ZLIB_STUB_H

#ifdef __cplusplus
extern "C" {
#endif

#define Z_OK                   0
#define Z_BUF_ERROR           (-5)
#define Z_DEFAULT_COMPRESSION (-1)
#define Z_BEST_SPEED           1
#define Z_BEST_COMPRESSION     9

typedef unsigned char Bytef;

static inline int compress2(Bytef* dest, unsigned long* destLen,
                            const Bytef* source, unsigned long sourceLen,
                            int level) {
    (void)dest; (void)source; (void)sourceLen; (void)level;
    if (destLen) *destLen = 0;
    return Z_BUF_ERROR;  // 호출되면 호출자가 압축 실패로 처리
}

static inline int uncompress(Bytef* dest, unsigned long* destLen,
                             const Bytef* source, unsigned long sourceLen) {
    (void)dest; (void)source; (void)sourceLen;
    if (destLen) *destLen = 0;
    return Z_BUF_ERROR;
}

#ifdef __cplusplus
}
#endif

#endif

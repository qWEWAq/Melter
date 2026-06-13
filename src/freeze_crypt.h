#ifndef MELTER_FREEZE_CRYPT_H
#define MELTER_FREEZE_CRYPT_H

#include <cstdint>

// eudplib/core/eudfunc/trace/tracecrypt.py 의 T, mix.
// armoha 의 freeze (현재 사용중) 는 이 eudplib 함수를 호출.
//
// phu54321 의 옛 freeze/crypt.py 는 T 1회 + mix 외부 T 없음 — 호환 안 됨.
//
//   T(x) = polynomial round x → x*(xsq*(xsq²+1)+1) + 0x8ada4053  반복 4회
//   mix(x, y) = T(T(x) + y + 0x10f874f3)   외부 T 한 번 더
//
// 모든 산술은 uint32_t 오버플로우로 자동 mod 2³² 처리됨.

// phu54321 (옛 freeze): T 1-round, mix = T(x) + y + c
inline uint32_t T2(uint32_t x) {
    uint32_t xsq = x * x;
    return x * (xsq * (xsq * xsq + 1u) + 1u) + 0x8ada4053u;
}

inline uint32_t freezeMix(uint32_t x, uint32_t y) {
    return T2(x) + y + 0x10f874f3u;
}

#endif  // MELTER_FREEZE_CRYPT_H

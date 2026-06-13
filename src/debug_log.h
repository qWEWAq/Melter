#ifndef MELTER_DEBUG_LOG_H
#define MELTER_DEBUG_LOG_H

// 전역 디버그 스위치.
//   저수준 모듈(mpqread / pts_runner / trig_emulate)이 내부 동작을 stderr 로 찍는
//   진단 출력을 게이트한다. 기본 false(조용) — CLI 의 --verbose 로만 켠다.
//   정의는 main.cpp. (이 출력들은 동작에 영향이 없는 순수 진단용이다.)
extern bool g_melterVerbose;

#endif  // MELTER_DEBUG_LOG_H

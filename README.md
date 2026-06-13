# melter — freeze 해제 CLI (정리판)

freeze 보호된 StarCraft: Remastered EUD 맵을 **복호화 + 편집가능화(defang) + 인게임
동작 보존**으로 해제하는 명령줄 도구. 불필요한 코드를 걷어내고 핵심 경로만 남긴 깔끔한 버전.

## freeze 보호의 두 자물쇠

| 자물쇠 | 내용 | melter 의 해제 |
|---|---|---|
| (A) 트리거 암호화 | 게임 트리거를 `actualKey` 로 XOR 암호화 | ① 복호화 |
| (B) obf-jump 난독화 | 복호화기의 점프 목적지를 매 프레임 "맵 지문(cryptKey)"으로 재계산 → 한 바이트만 고쳐도 점프가 어긋나 "편집 금지" 강제 | ② defang |

## 3단계 패치 (전부 scenario.chk 바이트 수정)

1. **복호화** — VM 을 1프레임 돌려 freeze 가 스스로 키를 메모리에 만들게 한 뒤,
   *"복호화 루프가 키를 슬롯에 self-modify 로 반복 복사한다"* 는 디컴파일 통찰(self-mod
   체인 랭킹)로 키 슬롯을 짚어 `actualKey` 를 복구한다. **브루트포스도, 전체 메모리
   스캔도 아니다.** 그 키로 암호화 트리거를 XOR 복호화한다. (실패 시에만 라이브 메모리
   스캔으로 폴백.)
2. **defang** — obf-jump 슬롯을 진짜 목적지 R 로 정적 고정하고 재계산/흔들림을 무력화
   → cryptKey 와 무관해져 **편집해도 안 깨진다.**
3. **in-place** — 패치된 scenario.chk 를 원본 MPQ 구조(헤더/블록·해시 테이블)를 보존하며
   같은 블록에 다시 써넣는다 → 게임이 정상적으로 맵을 읽는다.

## 사용법

```
melter <map.scx>                     복호화 + defang + in-place → <map>.unfrozen.scx
melter <map.scx> out.scx             출력 경로 지정
melter <map.scx> --rename-hex <hex>  위 + 맵 제목 변경 (UTF-8 hex, 길이 보존)
melter <map.scx> --decompile         freeze.py 함수 카테고리 해체 리포트만 출력
melter <map.scx> --chk-only          복호화한 scenario.chk 만 출력 (defang/repack 안 함)
```

옵션: `--verbose`(저수준 진단 출력), `--no-pause`(끝나면 바로 종료), `-h`

종료 코드: `0` 성공 / `2` 오류 / `3` freeze 맵 아님

## GUI (드래그 & 드롭 + 제목 변경)

`melter_gui.exe` — 창에 `.scx` 를 드래그&드롭하면 자동으로 해제해 `*.unfrozen.scx` 를
만든다. 상단 입력칸에 새 제목을 적으면 맵 제목도 함께 바꾼다(원본 제목 byte 길이 이내,
한글 1글자=3바이트). 내부적으로 `melter.exe <map> --no-pause [--rename-hex <hex>]` 를
호출하고 출력을 캡처해 결과(복호화 개수·저장 경로·제목 변경 여부)를 보여준다.
**`melter_gui.exe` 옆에 `melter.exe` 가 같이 있어야 한다.**

## 빌드

```
build_melter.bat   → melter.exe       (CLI)
build_gui.bat      → melter_gui.exe   (드래그&드롭 GUI, melter.exe 필요)
```

CLI 는 모든 의존 `.cpp` 를 직접 컴파일한다. (예외: `comp\imp.obj`·`comp\exp.obj` =
PKWARE implode/explode C 객체는 사전 빌드 재사용.) GUI 는 단일 Win32 파일
(`src\melter_gui.cpp`) 이다.

## 소스 구성 (src/)

| 파일 | 역할 |
|---|---|
| `main.cpp` | CLI 진입점 — 감지 → 복호화 → defang → in-place |
| `mpqread.cpp` / `mpq_writer.cpp` / `mpqcrypt.cpp` | MPQ 읽기 / 쓰기 / 해시·복호화 |
| `cmpdcmp.cpp` + `comp/*` | 블록 압축·해제 (PKWARE/huffman) |
| `chk_parse.cpp` | CHK 섹션(TRIG/STRx/SPRP…) 파싱·교체 |
| `eudplib_layout.cpp` | STRx 안 payload 위치·메모리 주소 계산 |
| `freeze_decrypt.cpp` / `freeze_keys.cpp` / `freeze_crypt.h` | 트리거 복호화 / 키 회수 / mix2 |
| `trig_emulate.cpp` / `pts_runner.cpp` / `vmemory.cpp` / `eud_vm.cpp` | 트리거 VM (1프레임 에뮬레이션) |
| `melter_gui.cpp` | 드래그&드롭 GUI (별도 빌드, `melter.exe` 호출) |

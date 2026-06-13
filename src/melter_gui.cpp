// ============================================================================
//  melter_gui — melter_final CLI 의 드래그&드롭 프런트엔드 (+ 맵 제목 수정)
// ============================================================================
//
//  .scx 맵을 창에 드래그&드롭(또는 exe 아이콘에 드롭)하면 melter.exe 를 호출해
//  freeze 를 자동 해제한다: 복호화 + obf-jump defang + in-place → <이름>.unfrozen.scx.
//  melter_final 의 CLI 는 기본 동작이 곧 "해제"이므로 별도 플래그 없이 호출한다
//  (원본 GUI 의 --auto 는 여기선 쓰지 않는다).
//
//  상단 입력칸에 새 제목을 적으면 그 맵의 제목도 함께 바꾼다. 제목은 UTF-8 hex 로
//  변환해 `--rename-hex <hex>` 로 넘긴다(ANSI argv 왕복에서 한글이 깨지지 않게).
//  제목 길이는 원본 제목의 byte 길이 이내여야 한다(한글 1글자 = 3바이트).
//
//  melter.exe 가 같은 폴더에 있어야 한다.
//  빌드: build_gui.bat   (MSVC, /SUBSYSTEM:WINDOWS, user32 shell32 gdi32)
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <string>
#include <vector>

static std::wstring g_exeDir;        // 이 exe 가 있는 폴더
static std::wstring g_melterPath;    // 같은 폴더의 melter.exe
static int   g_done = 0;             // 이번 세션 해제 성공 횟수
static HWND  g_edit = NULL;          // 제목 입력칸
static HFONT g_uiFont = NULL;
static HFONT g_titleFont = NULL;

// ───────────────────────────── 경로 유틸 ─────────────────────────────

static std::wstring exeDir() {
    wchar_t buf[MAX_PATH]; DWORD n = GetModuleFileNameW(NULL, buf, MAX_PATH);
    std::wstring p(buf, n);
    size_t s = p.find_last_of(L"\\/");
    return (s == std::wstring::npos) ? L"." : p.substr(0, s);
}

// melter 의 기본 출력 경로(<base>.unfrozen<ext>) — CLI 의 deriveOutputPath 와 동일 규칙.
static std::wstring unfrozenPath(const std::wstring& in) {
    size_t slash = in.find_last_of(L"\\/");
    size_t dot   = in.find_last_of(L'.');
    if (dot == std::wstring::npos || (slash != std::wstring::npos && dot < slash))
        return in + L".unfrozen.scx";
    return in.substr(0, dot) + L".unfrozen" + in.substr(dot);
}

// 새 제목(UTF-16) → UTF-8 바이트 → 대문자 hex 문자열.
static std::wstring titleToHex(const std::wstring& t) {
    if (t.empty()) return L"";
    int n = WideCharToMultiByte(CP_UTF8, 0, t.c_str(), (int)t.size(), NULL, 0, NULL, NULL);
    if (n <= 0) return L"";
    std::string u((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, t.c_str(), (int)t.size(), &u[0], n, NULL, NULL);
    static const wchar_t* H = L"0123456789ABCDEF";
    std::wstring hex;
    for (unsigned char c : u) { hex += H[c >> 4]; hex += H[c & 0xF]; }
    return hex;
}

// UTF-8 → UTF-16 (캡처한 melter 출력 표시용).
static std::wstring utf8ToW(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    std::wstring w((size_t)(n > 0 ? n : 0), 0);
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

// 캡처한 출력에서 needle 로 시작하는 줄을 한 줄 뽑아 (양끝 공백 제거) 반환. 없으면 빈 문자열.
static std::string lineContaining(const std::string& out, const std::string& needle) {
    size_t p = out.find(needle);
    if (p == std::string::npos) return "";
    size_t b = out.rfind('\n', p); b = (b == std::string::npos) ? 0 : b + 1;
    size_t e = out.find('\n', p);  if (e == std::string::npos) e = out.size();
    std::string s = out.substr(b, e - b);
    size_t s0 = s.find_first_not_of(" \t\r");
    size_t s1 = s.find_last_not_of(" \t\r");
    return (s0 == std::string::npos) ? "" : s.substr(s0, s1 - s0 + 1);
}

// ───────────────────────────── melter 실행 ─────────────────────────────

// melter.exe 를 자식 프로세스로 돌리고 stdout+stderr 를 파이프로 캡처. 종료코드 반환.
static std::string runMelter(const std::wstring& in, const std::wstring& titleHex, DWORD& exitCode) {
    exitCode = 2;
    SECURITY_ATTRIBUTES sa{}; sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;
    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return "pipe 생성 실패";
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    std::wstring cmd = L"\"" + g_melterPath + L"\" \"" + in + L"\" --no-pause";
    if (!titleHex.empty()) cmd += L" --rename-hex " + titleHex;
    std::vector<wchar_t> cbuf(cmd.begin(), cmd.end()); cbuf.push_back(0);

    STARTUPINFOW si{}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES; si.hStdOutput = wr; si.hStdError = wr;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(NULL, cbuf.data(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL,
                        g_exeDir.c_str(), &si, &pi)) {
        CloseHandle(rd); CloseHandle(wr);
        return "__NORUN__";
    }
    CloseHandle(wr);
    std::string out; char buf[8192]; DWORD n = 0;
    while (ReadFile(rd, buf, sizeof(buf), &n, NULL) && n > 0) out.append(buf, n);
    CloseHandle(rd);
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return out;
}

static void processFile(HWND hwnd, const std::wstring& in, const std::wstring& titleHex) {
    DWORD attr = GetFileAttributesW(in.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        MessageBoxW(hwnd, in.c_str(), L"melter — 파일을 찾을 수 없음", MB_ICONERROR);
        return;
    }
    DWORD code = 2;
    std::string out = runMelter(in, titleHex, code);

    if (out == "__NORUN__") {
        MessageBoxW(hwnd,
            (L"melter.exe 를 실행할 수 없습니다.\n같은 폴더에 melter.exe 가 있어야 합니다.\n\n찾은 경로:\n"
             + g_melterPath).c_str(),
            L"melter — 오류", MB_ICONERROR);
        return;
    }

    if (code == 0) {
        ++g_done;
        std::wstring outPath = utf8ToW(lineContaining(out, "output   :"));   // "output   : <경로>"
        std::wstring dec     = utf8ToW(lineContaining(out, "encrypted:"));   // "encrypted: N (decrypted M)"
        std::wstring msg = L"freeze 해제 완료! ✅\n\n";
        msg += dec.empty() ? L"" : (dec + L"\n\n");
        msg += outPath.empty() ? (L"저장: " + unfrozenPath(in)) : utf8ToW(lineContaining(out, "output   :"));
        if (!titleHex.empty()) {
            // melter 는 제목 변경 성공 시에만 "[rename] 맵 제목 변경 (N -> M bytes)" 를 찍는다.
            // 제목이 너무 길거나 제목 문자열이 없으면 "건너뜀" 을 찍고 그대로 성공 종료한다.
            // → ASCII 토큰 "bytes)" 의 유무로 성공/생략을 판정(한글 바이트 매칭보다 안전).
            if (out.find("bytes)") != std::string::npos)
                msg += L"\n\n맵 제목도 변경했습니다.";
            else
                msg += L"\n\n⚠ 새 제목이 원본보다 길어 제목 변경은 생략됐습니다 (한글 1글자=3바이트).";
        }
        msg += L"\n\n이제 이 맵은 복호화 + 편집 가능 + 인게임 실행됩니다.";
        MessageBoxW(hwnd, msg.c_str(), L"melter — 완료", MB_ICONINFORMATION);
    } else if (code == 3) {
        MessageBoxW(hwnd,
            (in + L"\n\n이 맵은 freeze 보호가 아닙니다. (변환할 것이 없습니다)").c_str(),
            L"melter — freeze 아님", MB_ICONINFORMATION);
    } else {
        std::wstring err = utf8ToW(lineContaining(out, "Error:"));
        MessageBoxW(hwnd,
            (in + L"\n\n처리에 실패했습니다.\n" +
             (err.empty() ? L"파일이 손상되었거나 표준 SCX/SCM 형식이 아닐 수 있습니다." : err)).c_str(),
            L"melter — 실패", MB_ICONERROR);
    }
    InvalidateRect(hwnd, NULL, TRUE);
}

// ───────────────────────────── 윈도우 ─────────────────────────────

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_CREATE: {
        DragAcceptFiles(h, TRUE);
        g_uiFont    = CreateFontW(17, 0, 0, 0, FW_NORMAL,   FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Malgun Gothic");
        g_titleFont = CreateFontW(26, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Malgun Gothic");
        HWND lbl = CreateWindowW(L"STATIC", L"새 맵 제목 (비우면 기존 제목 유지):",
            WS_CHILD | WS_VISIBLE, 18, 12, 520, 20, h, NULL, NULL, NULL);
        g_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 18, 34, 514, 28, h, (HMENU)1001, NULL, NULL);
        SendMessageW(lbl,    WM_SETFONT, (WPARAM)g_uiFont, TRUE);
        SendMessageW(g_edit, WM_SETFONT, (WPARAM)g_uiFont, TRUE);
        return 0;
    }
    case WM_DROPFILES: {
        wchar_t title[256] = {0};
        GetWindowTextW(g_edit, title, 256);
        std::wstring th = titleToHex(title);
        HDROP hd = (HDROP)w;
        UINT n = DragQueryFileW(hd, 0xFFFFFFFF, NULL, 0);
        for (UINT i = 0; i < n; ++i) {
            wchar_t f[MAX_PATH];
            if (DragQueryFileW(hd, i, f, MAX_PATH)) processFile(h, f, th);
        }
        DragFinish(hd);
        return 0;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps);
        RECT rc; GetClientRect(h, &rc);
        RECT area = rc; area.top = 80;            // 제목칸 아래
        SetBkMode(dc, TRANSPARENT);

        HFONT of = (HFONT)SelectObject(dc, g_titleFont);
        const wchar_t* title = L"여기에 .scx 맵을 드래그 & 드롭";
        RECT tr = area; tr.bottom = area.top + (rc.bottom - area.top) / 2;
        DrawTextW(dc, title, -1, &tr, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        SelectObject(dc, g_uiFont);
        SetTextColor(dc, RGB(90, 90, 90));
        wchar_t sub[256];
        wsprintfW(sub, L"freeze 자동 감지 → 복호화 + 편집가능 + 인게임 동작 → *.unfrozen.scx\n"
                       L"제목을 입력하면 함께 변경 (현재 제목 길이 이내, 한글 1글자=3바이트)\n\n"
                       L"이번 세션 해제: %d개", g_done);
        RECT sr = area; sr.top = area.top + (rc.bottom - area.top) / 2;
        DrawTextW(dc, sub, -1, &sr, DT_CENTER | DT_WORDBREAK);
        SelectObject(dc, of);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_CTLCOLORSTATIC:
        return (LRESULT)GetSysColorBrush(COLOR_WINDOW);
    case WM_DESTROY:
        if (g_uiFont) DeleteObject(g_uiFont);
        if (g_titleFont) DeleteObject(g_titleFont);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nShow) {
    g_exeDir = exeDir();
    g_melterPath = g_exeDir + L"\\melter.exe";

    WNDCLASSW wc{};
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"MelterFinalDropWnd";
    RegisterClassW(&wc);

    HWND h = CreateWindowExW(
        WS_EX_ACCEPTFILES, L"MelterFinalDropWnd", L"melter — freeze 자동 해제 + 맵 제목 변경",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 570, 340, NULL, NULL, hInst, NULL);
    ShowWindow(h, nShow);
    UpdateWindow(h);

    // exe 아이콘에 드롭된 파일은 명령줄 인자로 들어온다(제목칸 없음 → 이름 유지).
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        for (int i = 1; i < argc; ++i) processFile(h, argv[i], L"");
        LocalFree(argv);
    }

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}

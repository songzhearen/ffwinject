#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <commdlg.h>
#include <string>
#include <sstream>

#pragma comment(linker, "/SUBSYSTEM:WINDOWS")

// ============================================================================
// Constants
// ============================================================================

constexpr const wchar_t* TARGET_PROCESS  = L"FarFarWest-Win64-Shipping.exe";
constexpr const wchar_t* WINDOW_TITLE    = L"FarFarWest Mod Injector by songzhearen";
constexpr DWORD          POLL_INTERVAL   = 1000; // ms
constexpr int            WIN_W           = 460;
constexpr int            WIN_H           = 340;

// Control IDs
enum {
    IDC_DLL_EDIT    = 1001,
    IDC_BROWSE      = 1002,
    IDC_STATUS      = 1003,
    IDC_AUTOINJECT  = 1004,
    IDC_LOG         = 1005,
    IDC_INJECT      = 1006,
    IDT_POLL        = 2001,
};

// Application state
enum class AppState {
    NoDll,
    WaitingForProcess,
    Ready,
    Injecting,
    Success,
    AlreadyLoaded,
    Error,
};

// ============================================================================
// Globals
// ============================================================================

static HWND     g_hWnd         = nullptr;
static HWND     g_hDllEdit     = nullptr;
static HWND     g_hStatus      = nullptr;
static HWND     g_hLog         = nullptr;
static HWND     g_hInjectBtn   = nullptr;
static HWND     g_hAutoInject  = nullptr;
static AppState g_state        = AppState::NoDll;
static DWORD    g_foundPid     = 0;
static wchar_t  g_dllPath[MAX_PATH] = {};

// ============================================================================
// Helpers
// ============================================================================

static std::wstring FormatWin32Error(DWORD code) {
    wchar_t* buf = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                   nullptr, code, 0, reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
    std::wstring result = buf ? buf : L"Unknown error";
    LocalFree(buf);
    // trim trailing newlines
    while (!result.empty() && (result.back() == L'\n' || result.back() == L'\r'))
        result.pop_back();
    return result;
}

static void AppendLog(const wchar_t* text) {
    if (!g_hLog) return;
    int len = GetWindowTextLengthW(g_hLog);
    SendMessageW(g_hLog, EM_SETSEL, len, len);
    std::wstring line = std::wstring(text) + L"\r\n";
    SendMessageW(g_hLog, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(line.c_str()));
    // scroll to bottom
    SendMessageW(g_hLog, EM_SCROLLCARET, 0, 0);
}

static void SetStatus(const wchar_t* text) {
    if (g_hStatus) SetWindowTextW(g_hStatus, text);
}

// ============================================================================
// Process & Injection
// ============================================================================

static DWORD FindProcessByName(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static bool IsModuleLoaded(HANDLE hProcess, const wchar_t* dllName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));
    if (snap == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool found = false;

    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, dllName) == 0) {
                found = true;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

static bool InjectDll(DWORD pid, const wchar_t* dllPath, std::wstring& error) {
    // Get just the filename for module-already-loaded check
    const wchar_t* dllName = wcsrchr(dllPath, L'\\');
    dllName = dllName ? dllName + 1 : dllPath;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED)
            error = L"拒绝访问，请以管理员身份运行。";
        else
            error = L"OpenProcess 失败: " + FormatWin32Error(err);
        return false;
    }

    // Check if already loaded
    if (IsModuleLoaded(hProcess, dllName)) {
        CloseHandle(hProcess);
        error = L"__already_loaded__";
        return false;
    }

    size_t pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);

    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        error = L"VirtualAllocEx 失败: " + FormatWin32Error(GetLastError());
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, remoteMem, dllPath, pathSize, nullptr)) {
        error = L"WriteProcessMemory 失败: " + FormatWin32Error(GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    auto loadLibAddr = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
    if (!loadLibAddr) {
        error = L"获取 LoadLibraryW 地址失败。";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, loadLibAddr, remoteMem, 0, nullptr);
    if (!hThread) {
        error = L"CreateRemoteThread 失败: " + FormatWin32Error(GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, 10000);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);

    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    if (exitCode == 0) {
        error = L"DLL 在游戏内加载失败，请确认 DLL 为 64 位且依赖完整。";
        return false;
    }

    return true;
}

// ============================================================================
// UI State
// ============================================================================

static void UpdateUI() {
    // Read DLL path from edit
    GetWindowTextW(g_hDllEdit, g_dllPath, MAX_PATH);
    bool dllExists = (GetFileAttributesW(g_dllPath) != INVALID_FILE_ATTRIBUTES);

    switch (g_state) {
    case AppState::NoDll:
        SetStatus(L"DLL: 未选择或未找到");
        EnableWindow(g_hInjectBtn, FALSE);
        break;
    case AppState::WaitingForProcess:
        SetStatus(L"等待游戏进程 FarFarWest-Win64-Shipping.exe ...");
        EnableWindow(g_hInjectBtn, FALSE);
        break;
    case AppState::Ready: {
        wchar_t buf[128];
        swprintf_s(buf, L"已找到游戏进程 (PID: %u)，可以注入。", g_foundPid);
        SetStatus(buf);
        EnableWindow(g_hInjectBtn, dllExists);
        break;
    }
    case AppState::Injecting:
        SetStatus(L"正在注入...");
        EnableWindow(g_hInjectBtn, FALSE);
        break;
    case AppState::Success:
        SetStatus(L"注入成功！");
        EnableWindow(g_hInjectBtn, FALSE);
        break;
    case AppState::AlreadyLoaded:
        SetStatus(L"Mod 已在游戏中加载。");
        EnableWindow(g_hInjectBtn, FALSE);
        break;
    case AppState::Error:
        EnableWindow(g_hInjectBtn, FALSE);
        break;
    }
}

static void DoInject() {
    GetWindowTextW(g_hDllEdit, g_dllPath, MAX_PATH);
    if (GetFileAttributesW(g_dllPath) == INVALID_FILE_ATTRIBUTES) {
        AppendLog(L"[错误] DLL 文件未找到。");
        g_state = AppState::NoDll;
        UpdateUI();
        return;
    }

    if (g_foundPid == 0) {
        AppendLog(L"[错误] 游戏进程未找到。");
        g_state = AppState::WaitingForProcess;
        UpdateUI();
        return;
    }

    g_state = AppState::Injecting;
    UpdateUI();
    AppendLog(L"正在注入...");

    std::wstring error;
    bool ok = false;

    ok = InjectDll(g_foundPid, g_dllPath, error);

    if (ok) {
        g_state = AppState::Success;
        AppendLog(L"[成功] DLL 注入成功！");
    } else if (error == L"__already_loaded__") {
        g_state = AppState::AlreadyLoaded;
        AppendLog(L"[信息] Mod 已在游戏中加载。");
    } else {
        g_state = AppState::Error;
        SetStatus(error.c_str());
        std::wstring logMsg = L"[错误] " + error;
        AppendLog(logMsg.c_str());
    }
    UpdateUI();
}

// ============================================================================
// Timer / Polling
// ============================================================================

static void OnTimer() {
    GetWindowTextW(g_hDllEdit, g_dllPath, MAX_PATH);
    bool dllExists = (GetFileAttributesW(g_dllPath) != INVALID_FILE_ATTRIBUTES);

    if (!dllExists) {
        if (g_state != AppState::NoDll) {
            g_state = AppState::NoDll;
            UpdateUI();
        }
        return;
    }

    DWORD pid = FindProcessByName(TARGET_PROCESS);

    if (pid == 0) {
        if (g_state != AppState::WaitingForProcess && g_state != AppState::Success && g_state != AppState::AlreadyLoaded) {
            g_state = AppState::WaitingForProcess;
            g_foundPid = 0;
            UpdateUI();
        }
        // If we had success before and game closed, reset to waiting
        if (g_state == AppState::Success || g_state == AppState::AlreadyLoaded) {
            g_state = AppState::WaitingForProcess;
            g_foundPid = 0;
            AppendLog(L"[信息] 游戏进程已退出，等待新实例...");
            UpdateUI();
        }
        return;
    }

    // Process found
    if (g_state == AppState::WaitingForProcess || g_state == AppState::NoDll) {
        g_foundPid = pid;
        g_state = AppState::Ready;
        wchar_t buf[128];
        swprintf_s(buf, L"已找到游戏进程 (PID: %u)。", pid);
        AppendLog(buf);
        UpdateUI();

        // Auto-inject
        if (SendMessageW(g_hAutoInject, BM_GETCHECK, 0, 0) == BST_CHECKED) {
            DoInject();
        }
    } else if (g_state == AppState::Ready && pid != g_foundPid) {
        // Game restarted with new PID
        g_foundPid = pid;
        wchar_t buf[128];
        swprintf_s(buf, L"检测到新游戏实例 (PID: %u)。", pid);
        AppendLog(buf);
        UpdateUI();
    }
}

// ============================================================================
// Browse Dialog
// ============================================================================

static void BrowseDll() {
    wchar_t filePath[MAX_PATH] = {};

    OPENFILENAMEW ofn{};
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = g_hWnd;
    ofn.lpstrFilter  = L"DLL 文件 (*.dll)\0*.dll\0所有文件 (*.*)\0*.*\0";
    ofn.lpstrFile    = filePath;
    ofn.nMaxFile     = MAX_PATH;
    ofn.lpstrTitle   = L"选择 Mod DLL";
    ofn.Flags        = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (GetOpenFileNameW(&ofn)) {
        SetWindowTextW(g_hDllEdit, filePath);
        AppendLog((L"[信息] 已选择 DLL: " + std::wstring(filePath)).c_str());
        // Reset state so timer re-evaluates
        g_state = AppState::NoDll;
        UpdateUI();
    }
}

// ============================================================================
// Window Procedure
// ============================================================================

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BROWSE:
            BrowseDll();
            break;
        case IDC_INJECT:
            DoInject();
            break;
        }
        break;

    case WM_TIMER:
        if (wParam == IDT_POLL) OnTimer();
        break;

    case WM_CTLCOLORSTATIC: {
        HDC hdc = reinterpret_cast<HDC>(wParam);
        HWND hCtrl = reinterpret_cast<HWND>(lParam);
        if (hCtrl == g_hStatus || hCtrl == g_hLog) {
            SetBkMode(hdc, TRANSPARENT);
            return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_BTNFACE));
        }
        break;
    }

    case WM_DESTROY:
        KillTimer(hWnd, IDT_POLL);
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

// ============================================================================
// Entry Point
// ============================================================================

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    // Register window class
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hCursor       = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512)); // IDC_ARROW
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"FFWInjectorClass";
    RegisterClassExW(&wc);

    // Center on screen
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int posX = (screenW - WIN_W) / 2;
    int posY = (screenH - WIN_H) / 2;

    g_hWnd = CreateWindowExW(
        0, L"FFWInjectorClass", WINDOW_TITLE,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        posX, posY, WIN_W, WIN_H,
        nullptr, nullptr, hInstance, nullptr);

    if (!g_hWnd) return 1;

    // -- Controls --

    // DLL label
    CreateWindowExW(0, L"STATIC", L"DLL:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        12, 14, 30, 20, g_hWnd, nullptr, hInstance, nullptr);

    // DLL path edit
    g_hDllEdit = CreateWindowExW(0, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        42, 12, 320, 24, g_hWnd, reinterpret_cast<HMENU>(IDC_DLL_EDIT), hInstance, nullptr);

    // Browse button
    CreateWindowExW(0, L"BUTTON", L"浏览...",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        368, 12, 72, 24, g_hWnd, reinterpret_cast<HMENU>(IDC_BROWSE), hInstance, nullptr);

    // Status label
    g_hStatus = CreateWindowExW(0, L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        12, 46, 428, 20, g_hWnd, reinterpret_cast<HMENU>(IDC_STATUS), hInstance, nullptr);

    // Auto-inject checkbox
    g_hAutoInject = CreateWindowExW(0, L"BUTTON", L"自动注入",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        12, 72, 120, 20, g_hWnd, reinterpret_cast<HMENU>(IDC_AUTOINJECT), hInstance, nullptr);

    // Log edit (multiline, readonly)
    g_hLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        12, 100, 428, 170, g_hWnd, reinterpret_cast<HMENU>(IDC_LOG), hInstance, nullptr);

    // Inject button
    g_hInjectBtn = CreateWindowExW(0, L"BUTTON", L"注入",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_DEFPUSHBUTTON,
        180, 278, 100, 28, g_hWnd, reinterpret_cast<HMENU>(IDC_INJECT), hInstance, nullptr);

    // Set font (Microsoft YaHei for Chinese support)
    HFONT hFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei");
    if (hFont) {
        auto setFont = [&](HWND h) { SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(hFont), TRUE); };
        setFont(g_hDllEdit);
        setFont(g_hStatus);
        setFont(g_hLog);
        setFont(g_hInjectBtn);
        setFont(g_hAutoInject);
        // Also set font for the static labels (DLL:, etc.)
        EnumChildWindows(g_hWnd, [](HWND hChild, LPARAM lParam) -> BOOL {
            SendMessageW(hChild, WM_SETFONT, static_cast<WPARAM>(lParam), TRUE);
            return TRUE;
        }, reinterpret_cast<LPARAM>(hFont));
    }

    // Initial state
    g_state = AppState::NoDll;
    UpdateUI();
    AppendLog(L"FarFarWest Mod Injector by songzhearen");
    AppendLog(L"请选择 DLL 文件，然后点击注入。");

    // Start polling timer
    SetTimer(g_hWnd, IDT_POLL, POLL_INTERVAL, nullptr);

    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);

    // Message loop
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN) {
            // Enter key triggers inject if button is enabled
            if (IsWindowEnabled(g_hInjectBtn)) {
                DoInject();
                continue;
            }
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return static_cast<int>(msg.wParam);
}

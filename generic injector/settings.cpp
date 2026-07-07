#include "framework.h"
#include "generic injector.h"

static std::wstring GetSettingsPath() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring path(exePath);
    size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        path = path.substr(0, pos + 1) + L"settings.ini";
    }
    return path;
}

void SaveSettings(const InjectionSettings& settings) {
    std::wstring path = GetSettingsPath();
    WritePrivateProfileStringW(L"Settings", L"DllPath", settings.dllPath.c_str(), path.c_str());
    WritePrivateProfileStringW(L"Settings", L"Method", std::to_wstring((int)settings.method).c_str(), path.c_str());
    WritePrivateProfileStringW(L"Settings", L"Scramble", settings.scrambleDll ? L"1" : L"0", path.c_str());
    WritePrivateProfileStringW(L"Settings", L"CloseOnInject", settings.closeOnInject ? L"1" : L"0", path.c_str());
    WritePrivateProfileStringW(L"Settings", L"StealthMode", settings.stealthMode ? L"1" : L"0", path.c_str());
    WritePrivateProfileStringW(L"Settings", L"UnlinkFromPEB", settings.unlinkFromPeb ? L"1" : L"0", path.c_str());
}

void LoadSettings(InjectionSettings& settings) {
    std::wstring path = GetSettingsPath();
    wchar_t buf[MAX_PATH];
    
    GetPrivateProfileStringW(L"Settings", L"DllPath", L"", buf, MAX_PATH, path.c_str());
    settings.dllPath = buf;
    
    settings.method = (InjectionMethod)GetPrivateProfileIntW(L"Settings", L"Method", 0, path.c_str());
    settings.scrambleDll = GetPrivateProfileIntW(L"Settings", L"Scramble", 0, path.c_str()) != 0;
    settings.closeOnInject = GetPrivateProfileIntW(L"Settings", L"CloseOnInject", 0, path.c_str()) != 0;
    settings.stealthMode = GetPrivateProfileIntW(L"Settings", L"StealthMode", 0, path.c_str()) != 0;
    settings.unlinkFromPeb = GetPrivateProfileIntW(L"Settings", L"UnlinkFromPEB", 0, path.c_str()) != 0;
}

void CreateSettingsControls(HWND hParent, HINSTANCE hInst) {
    RECT rc;
    GetClientRect(hParent, &rc);
    TabCtrl_AdjustRect(g_hTab, FALSE, &rc);
    
    int clientW = rc.right - rc.left;
    int baseY = rc.top;
    
    g_hGrpInjection = CreateWindowW(L"BUTTON", L"Injection Settings", WS_CHILD | BS_GROUPBOX, 10, baseY + 5, clientW - 20, 110, hParent, nullptr, hInst, nullptr);
    g_hLblDll = CreateWindowW(L"STATIC", L"DLL Path:", WS_CHILD, 25, baseY + 30, 60, 20, hParent, nullptr, hInst, nullptr);
    g_hEditDllPath = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 90, baseY + 28, clientW - 190, 22, hParent, (HMENU)IDC_EDIT_DLL_PATH, hInst, nullptr);
    g_hBtnBrowse = CreateWindowW(L"BUTTON", L"Browse", WS_CHILD | BS_PUSHBUTTON, clientW - 90, baseY + 27, 70, 24, hParent, (HMENU)IDC_BTN_BROWSE, hInst, nullptr);
    g_hLblMethod = CreateWindowW(L"STATIC", L"Method:", WS_CHILD, 25, baseY + 65, 60, 20, hParent, nullptr, hInst, nullptr);
    g_hComboMethod = CreateWindowW(L"COMBOBOX", L"", WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL, 90, baseY + 62, 200, 200, hParent, (HMENU)IDC_COMBO_METHOD, hInst, nullptr);
    
    SendMessageW(g_hComboMethod, CB_ADDSTRING, 0, (LPARAM)L"LoadLibraryW");
    SendMessageW(g_hComboMethod, CB_ADDSTRING, 0, (LPARAM)L"Manual Map");
    SendMessageW(g_hComboMethod, CB_ADDSTRING, 0, (LPARAM)L"NtCreateThreadEx");
    SendMessageW(g_hComboMethod, CB_ADDSTRING, 0, (LPARAM)L"Thread Hijack");
    
    g_hGrpOptions = CreateWindowW(L"BUTTON", L"Options", WS_CHILD | BS_GROUPBOX, 10, baseY + 125, clientW - 20, 160, hParent, nullptr, hInst, nullptr);
    g_hChkScramble = CreateWindowW(L"BUTTON", L"Scramble DLL before injection", WS_CHILD | BS_AUTOCHECKBOX, 25, baseY + 150, 280, 20, hParent, (HMENU)IDC_CHK_SCRAMBLE, hInst, nullptr);
    g_hChkClose = CreateWindowW(L"BUTTON", L"Close after successful injection", WS_CHILD | BS_AUTOCHECKBOX, 25, baseY + 175, 280, 20, hParent, (HMENU)IDC_CHK_CLOSE, hInst, nullptr);
    g_hChkStealth = CreateWindowW(L"BUTTON", L"Stealth mode (erase PE headers)", WS_CHILD | BS_AUTOCHECKBOX, 25, baseY + 200, 300, 20, hParent, (HMENU)IDC_CHK_STEALTH, hInst, nullptr);
    g_hChkUnlink = CreateWindowW(L"BUTTON", L"Unlink module from PEB", WS_CHILD | BS_AUTOCHECKBOX, 25, baseY + 225, 280, 20, hParent, (HMENU)IDC_CHK_UNLINK, hInst, nullptr);
    
    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    SendMessage(g_hGrpInjection, WM_SETFONT, (WPARAM)hFont, FALSE);
    SendMessage(g_hLblDll, WM_SETFONT, (WPARAM)hFont, FALSE);
    SendMessage(g_hEditDllPath, WM_SETFONT, (WPARAM)hFont, FALSE);
    SendMessage(g_hBtnBrowse, WM_SETFONT, (WPARAM)hFont, FALSE);
    SendMessage(g_hLblMethod, WM_SETFONT, (WPARAM)hFont, FALSE);
    SendMessage(g_hComboMethod, WM_SETFONT, (WPARAM)hFont, FALSE);
    SendMessage(g_hGrpOptions, WM_SETFONT, (WPARAM)hFont, FALSE);
    SendMessage(g_hChkScramble, WM_SETFONT, (WPARAM)hFont, FALSE);
    SendMessage(g_hChkClose, WM_SETFONT, (WPARAM)hFont, FALSE);
    SendMessage(g_hChkStealth, WM_SETFONT, (WPARAM)hFont, FALSE);
    SendMessage(g_hChkUnlink, WM_SETFONT, (WPARAM)hFont, FALSE);
}

void ShowSettingsControls(bool show) {
    int cmdShow = show ? SW_SHOW : SW_HIDE;
    ShowWindow(g_hGrpInjection, cmdShow);
    ShowWindow(g_hLblDll, cmdShow);
    ShowWindow(g_hEditDllPath, cmdShow);
    ShowWindow(g_hBtnBrowse, cmdShow);
    ShowWindow(g_hLblMethod, cmdShow);
    ShowWindow(g_hComboMethod, cmdShow);
    ShowWindow(g_hGrpOptions, cmdShow);
    ShowWindow(g_hChkScramble, cmdShow);
    ShowWindow(g_hChkClose, cmdShow);
    ShowWindow(g_hChkStealth, cmdShow);
    ShowWindow(g_hChkUnlink, cmdShow);
}

void ShowProcessControls(bool show) {
    int cmdShow = show ? SW_SHOW : SW_HIDE;
    ShowWindow(g_hListView, cmdShow);
    ShowWindow(g_hFilterEdit, cmdShow);
    ShowWindow(g_hBtnRefresh, cmdShow);
}

void UpdateSettingsFromControls(InjectionSettings& settings) {
    wchar_t buf[MAX_PATH];
    GetWindowTextW(g_hEditDllPath, buf, MAX_PATH);
    settings.dllPath = buf;
    
    settings.method = (InjectionMethod)SendMessage(g_hComboMethod, CB_GETCURSEL, 0, 0);
    settings.scrambleDll = SendMessage(g_hChkScramble, BM_GETCHECK, 0, 0) == BST_CHECKED;
    settings.closeOnInject = SendMessage(g_hChkClose, BM_GETCHECK, 0, 0) == BST_CHECKED;
    settings.stealthMode = SendMessage(g_hChkStealth, BM_GETCHECK, 0, 0) == BST_CHECKED;
    settings.unlinkFromPeb = SendMessage(g_hChkUnlink, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

void ApplySettingsToControls(const InjectionSettings& settings) {
    SetWindowTextW(g_hEditDllPath, settings.dllPath.c_str());
    SendMessage(g_hComboMethod, CB_SETCURSEL, (WPARAM)settings.method, 0);
    SendMessage(g_hChkScramble, BM_SETCHECK, settings.scrambleDll ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessage(g_hChkClose, BM_SETCHECK, settings.closeOnInject ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessage(g_hChkStealth, BM_SETCHECK, settings.stealthMode ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessage(g_hChkUnlink, BM_SETCHECK, settings.unlinkFromPeb ? BST_CHECKED : BST_UNCHECKED, 0);
}

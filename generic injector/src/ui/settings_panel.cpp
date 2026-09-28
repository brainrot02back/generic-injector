#include "api.h"

namespace gi {

std::wstring get_settings_path() {
    wchar_t exe_path[MAX_PATH];
    GetModuleFileNameW(nullptr, exe_path, MAX_PATH);

    std::wstring path(exe_path);
    const size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        path = path.substr(0, pos + 1) + L"settings.ini";
    }
    return path;
}

void save_settings(const injection_settings& settings) {
    const std::wstring path = get_settings_path();

    WritePrivateProfileStringW(L"Settings", L"DllPath", settings.dll_path.c_str(), path.c_str());
    WritePrivateProfileStringW(L"Settings", L"Method",
                               std::to_wstring(static_cast<int>(settings.method)).c_str(), path.c_str());
    WritePrivateProfileStringW(L"Settings", L"Scramble",         settings.scramble_dll     ? L"1" : L"0", path.c_str());
    WritePrivateProfileStringW(L"Settings", L"CloseOnInject",   settings.close_on_inject ? L"1" : L"0", path.c_str());
    WritePrivateProfileStringW(L"Settings", L"StealthMode",     settings.stealth_mode    ? L"1" : L"0", path.c_str());
    WritePrivateProfileStringW(L"Settings", L"UnlinkFromPEB",   settings.unlink_from_peb ? L"1" : L"0", path.c_str());
}

void load_settings(injection_settings& settings) {
    const std::wstring path = get_settings_path();

    wchar_t buf[MAX_PATH] = {};
    GetPrivateProfileStringW(L"Settings", L"DllPath", L"", buf, MAX_PATH, path.c_str());
    settings.dll_path = buf;

    settings.method = static_cast<injection_method>(
        GetPrivateProfileIntW(L"Settings", L"Method", 0, path.c_str()));
    settings.scramble_dll     = GetPrivateProfileIntW(L"Settings", L"Scramble",       0, path.c_str()) != 0;
    settings.close_on_inject = GetPrivateProfileIntW(L"Settings", L"CloseOnInject", 0, path.c_str()) != 0;
    settings.stealth_mode    = GetPrivateProfileIntW(L"Settings", L"StealthMode",   0, path.c_str()) != 0;
    settings.unlink_from_peb = GetPrivateProfileIntW(L"Settings", L"UnlinkFromPEB", 0, path.c_str()) != 0;
}

void create_settings_controls(HWND parent, HINSTANCE inst) {
    RECT rc;
    GetClientRect(parent, &rc);
    TabCtrl_AdjustRect(g_tab, FALSE, &rc);

    const int client_w = rc.right - rc.left;
    const int base_y   = rc.top;

    g_grp_injection = CreateWindowW(L"BUTTON", L"Injection Settings", WS_CHILD | BS_GROUPBOX,
                                    10, base_y + 5, client_w - 20, 110, parent, nullptr, inst, nullptr);
    g_lbl_dll       = CreateWindowW(L"STATIC", L"DLL Path:", WS_CHILD,
                                    25, base_y + 30, 60, 20, parent, nullptr, inst, nullptr);
    g_edit_dll_path = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
                                    90, base_y + 28, client_w - 190, 22, parent, (HMENU)IDC_EDIT_DLL_PATH, inst, nullptr);
    g_btn_browse    = CreateWindowW(L"BUTTON", L"Browse", WS_CHILD | BS_PUSHBUTTON,
                                    client_w - 90, base_y + 27, 70, 24, parent, (HMENU)IDC_BTN_BROWSE, inst, nullptr);
    g_lbl_method    = CreateWindowW(L"STATIC", L"Method:", WS_CHILD,
                                    25, base_y + 65, 60, 20, parent, nullptr, inst, nullptr);
    g_combo_method  = CreateWindowW(L"COMBOBOX", L"", WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL,
                                    90, base_y + 62, 200, 200, parent, (HMENU)IDC_COMBO_METHOD, inst, nullptr);

    SendMessageW(g_combo_method, CB_ADDSTRING, 0, (LPARAM)L"LoadLibraryW");
    SendMessageW(g_combo_method, CB_ADDSTRING, 0, (LPARAM)L"Manual Map");
    SendMessageW(g_combo_method, CB_ADDSTRING, 0, (LPARAM)L"NtCreateThreadEx");
    SendMessageW(g_combo_method, CB_ADDSTRING, 0, (LPARAM)L"Thread Hijack");

    g_grp_options   = CreateWindowW(L"BUTTON", L"Options", WS_CHILD | BS_GROUPBOX,
                                    10, base_y + 125, client_w - 20, 160, parent, nullptr, inst, nullptr);
    g_chk_scramble  = CreateWindowW(L"BUTTON", L"Scramble DLL before injection", WS_CHILD | BS_AUTOCHECKBOX,
                                    25, base_y + 150, 280, 20, parent, (HMENU)IDC_CHK_SCRAMBLE, inst, nullptr);
    g_chk_close     = CreateWindowW(L"BUTTON", L"Close after successful injection", WS_CHILD | BS_AUTOCHECKBOX,
                                    25, base_y + 175, 280, 20, parent, (HMENU)IDC_CHK_CLOSE, inst, nullptr);
    g_chk_stealth   = CreateWindowW(L"BUTTON", L"Stealth mode (erase PE headers)", WS_CHILD | BS_AUTOCHECKBOX,
                                    25, base_y + 200, 300, 20, parent, (HMENU)IDC_CHK_STEALTH, inst, nullptr);
    g_chk_unlink    = CreateWindowW(L"BUTTON", L"Unlink module from PEB", WS_CHILD | BS_AUTOCHECKBOX,
                                    25, base_y + 225, 280, 20, parent, (HMENU)IDC_CHK_UNLINK, inst, nullptr);

    HFONT font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    const HWND controls[] = {
        g_grp_injection, g_lbl_dll,    g_edit_dll_path, g_btn_browse, g_lbl_method,
        g_combo_method,  g_grp_options, g_chk_scramble, g_chk_close,   g_chk_stealth,
        g_chk_unlink
    };
    for (HWND control : controls) {
        SendMessage(control, WM_SETFONT, (WPARAM)font, FALSE);
    }
}

void show_settings_controls(bool show) {
    const int cmd_show = show ? SW_SHOW : SW_HIDE;

    const HWND controls[] = {
        g_grp_injection, g_lbl_dll,    g_edit_dll_path, g_btn_browse, g_lbl_method,
        g_combo_method,  g_grp_options, g_chk_scramble, g_chk_close,   g_chk_stealth,
        g_chk_unlink
    };
    for (HWND control : controls) {
        ShowWindow(control, cmd_show);
    }
}

void show_process_controls(bool show) {
    const int cmd_show = show ? SW_SHOW : SW_HIDE;
    ShowWindow(g_list_view, cmd_show);
    ShowWindow(g_filter_edit, cmd_show);
    ShowWindow(g_btn_refresh, cmd_show);
}

void update_settings_from_controls(injection_settings& settings) {
    wchar_t buf[MAX_PATH] = {};
    GetWindowTextW(g_edit_dll_path, buf, MAX_PATH);
    settings.dll_path = buf;

    settings.method = static_cast<injection_method>(SendMessage(g_combo_method, CB_GETCURSEL, 0, 0));
    settings.scramble_dll     = SendMessage(g_chk_scramble, BM_GETCHECK, 0, 0) == BST_CHECKED;
    settings.close_on_inject = SendMessage(g_chk_close,    BM_GETCHECK, 0, 0) == BST_CHECKED;
    settings.stealth_mode    = SendMessage(g_chk_stealth,  BM_GETCHECK, 0, 0) == BST_CHECKED;
    settings.unlink_from_peb = SendMessage(g_chk_unlink,   BM_GETCHECK, 0, 0) == BST_CHECKED;
}

void apply_settings_to_controls(const injection_settings& settings) {
    SetWindowTextW(g_edit_dll_path, settings.dll_path.c_str());
    SendMessage(g_combo_method, CB_SETCURSEL, (WPARAM)settings.method, 0);
    SendMessage(g_chk_scramble, BM_SETCHECK, settings.scramble_dll     ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessage(g_chk_close,    BM_SETCHECK, settings.close_on_inject ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessage(g_chk_stealth,  BM_SETCHECK, settings.stealth_mode    ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessage(g_chk_unlink,   BM_SETCHECK, settings.unlink_from_peb ? BST_CHECKED : BST_UNCHECKED, 0);
}

} // namespace gi

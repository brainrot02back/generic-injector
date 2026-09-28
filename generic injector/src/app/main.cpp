#include "api.h"

namespace gi {

LRESULT CALLBACK window_proc(HWND hwnd, UINT message, WPARAM w_param, LPARAM l_param);

constexpr UINT_PTR TIMER_STATS            = 1;
constexpr UINT    TIMER_STATS_INTERVAL_MS = 2000;

static ATOM register_window_class(HINSTANCE inst) {
    WNDCLASSEXW wcex{};
    wcex.cbSize        = sizeof(WNDCLASSEXW);
    wcex.style         = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc   = window_proc;
    wcex.cbClsExtra    = 0;
    wcex.cbWndExtra    = 0;
    wcex.hInstance     = inst;
    wcex.hIcon         = LoadIcon(inst, MAKEINTRESOURCE(IDI_GENERICINJECTOR));
    wcex.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName  = nullptr;
    wcex.lpszClassName = g_class_name;
    wcex.hIconSm       = LoadIcon(inst, MAKEINTRESOURCE(IDI_SMALL));
    return RegisterClassExW(&wcex);
}

static BOOL init_instance(HINSTANCE inst, int show_cmd) {
    g_hinst = inst;

    HWND hwnd = CreateWindowW(g_class_name, L"Generic Injector",
                              WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                              CW_USEDEFAULT, 0, 900, 600,
                              nullptr, nullptr, inst, nullptr);
    if (!hwnd) return FALSE;

    ShowWindow(hwnd, show_cmd);
    UpdateWindow(hwnd);
    return TRUE;
}

static void setup_columns(HWND list_view) {
    struct column_def {
        int         sub_item;
        const wchar_t* title;
        int         width;
        int         fmt;
    };

    static const column_def columns[] = {
        { 0, L"Process Name", 200, LVCFMT_LEFT   },
        { 1, L"PID",            60, LVCFMT_RIGHT  },
        { 2, L"CPU%",           60, LVCFMT_RIGHT  },
        { 3, L"RAM(MB)",        70, LVCFMT_RIGHT  },
        { 4, L"Arch",           50, LVCFMT_CENTER },
        { 5, L"Window Title",  200, LVCFMT_LEFT   },
        { 6, L"Path",          300, LVCFMT_LEFT   },
    };

    LVCOLUMNW lvc{};
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;

    for (const auto& col : columns) {
        lvc.iSubItem = col.sub_item;
        lvc.pszText  = const_cast<LPWSTR>(col.title);
        lvc.cx       = col.width;
        lvc.fmt      = col.fmt;
        ListView_InsertColumn(list_view, col.sub_item, &lvc);
    }
}

static void create_controls(HWND hwnd, HINSTANCE inst) {
    HFONT font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    g_tab = CreateWindowW(WC_TABCONTROL, L"", WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE,
                          0, 0, 0, 0, hwnd, (HMENU)IDC_TAB_MAIN, inst, nullptr);
    SendMessage(g_tab, WM_SETFONT, (WPARAM)font, FALSE);

    TCITEMW tie{};
    tie.mask    = TCIF_TEXT | TCIF_IMAGE;
    tie.iImage  = -1;
    tie.pszText = const_cast<LPWSTR>(L"Processes");
    TabCtrl_InsertItem(g_tab, 0, &tie);
    tie.pszText = const_cast<LPWSTR>(L"Settings");
    TabCtrl_InsertItem(g_tab, 1, &tie);

    g_filter_edit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                                  0, 0, 0, 0, hwnd, (HMENU)IDC_EDIT_FILTER, inst, nullptr);
    SendMessage(g_filter_edit, WM_SETFONT, (WPARAM)font, FALSE);
    SendMessage(g_filter_edit, EM_SETCUEBANNER, FALSE, (LPARAM)L"Search Processes...");

    g_btn_refresh = CreateWindowW(L"BUTTON", L"Refresh", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                  0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_REFRESH, inst, nullptr);
    SendMessage(g_btn_refresh, WM_SETFONT, (WPARAM)font, FALSE);

    g_list_view = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEW, L"",
                                  WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                  0, 0, 0, 0, hwnd, (HMENU)IDC_PROCESS_LIST, inst, nullptr);
    ListView_SetExtendedListViewStyle(g_list_view, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    SendMessage(g_list_view, WM_SETFONT, (WPARAM)font, FALSE);

    setup_columns(g_list_view);

    create_settings_controls(hwnd, inst);
    show_settings_controls(false);

    g_status_bar = CreateWindowW(STATUSCLASSNAME, L"", WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                                 0, 0, 0, 0, hwnd, (HMENU)IDC_STATUSBAR, inst, nullptr);
    SendMessage(g_status_bar, SB_SETTEXT, 0, (LPARAM)L"Ready");

    g_btn_inject = CreateWindowW(L"BUTTON", L"INJECT", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_INJECT, inst, nullptr);
    SendMessage(g_btn_inject, WM_SETFONT, (WPARAM)font, FALSE);
}

static void handle_layout(LPARAM l_param) {
    const int width  = LOWORD(l_param);
    const int height = HIWORD(l_param);

    const int status_height      = 22;
    const int inject_btn_height  = 40;
    const int tab_height = height - status_height - inject_btn_height - 10;

    SendMessage(g_status_bar, WM_SIZE, 0, 0);

    MoveWindow(g_tab, 5, 5, width - 10, tab_height, TRUE);
    MoveWindow(g_btn_inject, width / 2 - 100, height - status_height - inject_btn_height - 5,
               200, inject_btn_height, TRUE);

    RECT tab_rect;
    GetClientRect(g_tab, &tab_rect);
    TabCtrl_AdjustRect(g_tab, FALSE, &tab_rect);

    const int tab_x = tab_rect.left + 5;
    const int tab_y = tab_rect.top + 5;
    const int tab_w = tab_rect.right  - tab_rect.left;
    const int tab_h = tab_rect.bottom - tab_rect.top;

    MoveWindow(g_filter_edit, tab_x, tab_y, tab_w - 80, 22, TRUE);
    MoveWindow(g_btn_refresh, tab_x + tab_w - 75, tab_y, 75, 22, TRUE);
    MoveWindow(g_list_view, tab_x, tab_y + 27, tab_w, tab_h - 27, TRUE);
}

static void handle_notify(LPARAM l_param) {
    auto* hdr = reinterpret_cast<LPNMHDR>(l_param);
    if (!hdr) return;

    if (hdr->hwndFrom == g_tab && hdr->code == TCN_SELCHANGE) {
        const int sel = TabCtrl_GetCurSel(g_tab);
        if (sel == 0) {
            show_settings_controls(false);
            show_process_controls(true);
        } else if (sel == 1) {
            show_process_controls(false);
            show_settings_controls(true);
        }
        return;
    }

    if (hdr->hwndFrom != g_list_view) return;

    auto* nmv = reinterpret_cast<LPNMLISTVIEW>(l_param);

    if (hdr->code == LVN_ITEMCHANGED) {
        if ((nmv->uChanged & LVIF_STATE) && (nmv->uNewState & LVIS_SELECTED)) {
            g_selected_pid = (DWORD)nmv->lParam;
            wchar_t buf[256];
            swprintf_s(buf, L"Selected PID: %u", g_selected_pid);
            SendMessage(g_status_bar, SB_SETTEXT, 0, (LPARAM)buf);
        }
    } else if (hdr->code == LVN_COLUMNCLICK) {
        if (g_sort_column == nmv->iSubItem) {
            g_sort_ascending = !g_sort_ascending;
        } else {
            g_sort_column     = nmv->iSubItem;
            g_sort_ascending  = true;
        }
        ListView_SortItemsEx(g_list_view, compare_list_items, (LPARAM)g_list_view);
    }
}

static void handle_browse(HWND hwnd) {
    wchar_t file[MAX_PATH] = {};
    OPENFILENAMEW ofn{};
    ofn.lStructSize     = sizeof(ofn);
    ofn.hwndOwner       = hwnd;
    ofn.lpstrFile       = file;
    ofn.nMaxFile        = MAX_PATH;
    ofn.lpstrFilter     = L"DLL Files (*.dll)\0*.dll\0All Files (*.*)\0*.*\0";
    ofn.nFilterIndex    = 1;
    ofn.Flags           = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameW(&ofn) == TRUE) {
        SetWindowTextW(g_edit_dll_path, ofn.lpstrFile);
    }
}

static void handle_inject(HWND hwnd) {
    update_settings_from_controls(g_settings);
    save_settings(g_settings);

    if (g_selected_pid == 0) {
        MessageBoxW(hwnd, L"Please select a target process first.", L"Error", MB_ICONERROR);
        return;
    }

    if (g_settings.dll_path.empty() ||
        GetFileAttributesW(g_settings.dll_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(hwnd, L"Please select a valid DLL file.", L"Error", MB_ICONERROR);
        TabCtrl_SetCurSel(g_tab, 1);
        show_process_controls(false);
        show_settings_controls(true);
        return;
    }

    SendMessage(g_status_bar, SB_SETTEXT, 0, (LPARAM)L"Injecting...");

    const injection_result result = perform_injection(g_selected_pid, g_settings);
    SendMessage(g_status_bar, SB_SETTEXT, 0, (LPARAM)result.message.c_str());

    if (result.success && g_settings.close_on_inject) {
        PostMessage(hwnd, WM_CLOSE, 0, 0);
    } else if (!result.success) {
        MessageBoxW(hwnd, result.message.c_str(), L"Injection Failed", MB_ICONERROR);
    }

    cleanup_scrambled_files();
}

static void handle_command(HWND hwnd, WPARAM w_param) {
    const int wm_id = LOWORD(w_param);

    switch (wm_id) {
    case IDC_BTN_REFRESH: {
        wchar_t filter[256] = {};
        GetWindowTextW(g_filter_edit, filter, 256);
        enumerate_processes(g_processes);
        populate_list_view(g_list_view, g_processes, filter);
        break;
    }
    case IDC_EDIT_FILTER: {
        if (HIWORD(w_param) != EN_CHANGE) return;
        wchar_t filter[256] = {};
        GetWindowTextW(g_filter_edit, filter, 256);
        populate_list_view(g_list_view, g_processes, filter);
        break;
    }
    case IDC_BTN_BROWSE:
        handle_browse(hwnd);
        break;
    case IDC_BTN_INJECT:
        handle_inject(hwnd);
        return; 
    default:
        update_settings_from_controls(g_settings);
        save_settings(g_settings);
        break;
    }
}

static void update_live_stats() {
    refresh_process_stats(g_processes);

    const int count = ListView_GetItemCount(g_list_view);
    for (int i = 0; i < count; ++i) {
        LVITEMW lvi{};
        lvi.iItem = i;
        lvi.mask  = LVIF_PARAM;
        ListView_GetItem(g_list_view, &lvi);

        auto it = std::find_if(g_processes.begin(), g_processes.end(),
                               [pid = (DWORD)lvi.lParam](const process_entry& e) { return e.pid == pid; });
        if (it == g_processes.end()) continue;

        wchar_t cpu_buf[32];
        swprintf_s(cpu_buf, L"%.2f%%", it->cpu_usage);
        ListView_SetItemText(g_list_view, i, 2, cpu_buf);

        const std::wstring memory_text = std::to_wstring(it->memory_usage_kb / 1024);
        ListView_SetItemText(g_list_view, i, 3, const_cast<LPWSTR>(memory_text.c_str()));
    }
}

LRESULT CALLBACK window_proc(HWND hwnd, UINT message, WPARAM w_param, LPARAM l_param) {
    switch (message) {
    case WM_CREATE: {
        create_controls(hwnd, g_hinst);

        load_settings(g_settings);
        apply_settings_to_controls(g_settings);

        enumerate_processes(g_processes);
        populate_list_view(g_list_view, g_processes, L"");

        SetTimer(hwnd, TIMER_STATS, TIMER_STATS_INTERVAL_MS, nullptr);
        break;
    }
    case WM_SIZE:
        handle_layout(l_param);
        break;
    case WM_NOTIFY:
        handle_notify(l_param);
        break;
    case WM_COMMAND:
        handle_command(hwnd, w_param);
        break;
    case WM_TIMER:
        if (w_param == TIMER_STATS && TabCtrl_GetCurSel(g_tab) == 0) {
            update_live_stats();
        }
        break;
    case WM_DESTROY:
        KillTimer(hwnd, TIMER_STATS);
        if (g_image_list) {
            ImageList_Destroy(g_image_list);
            g_image_list = nullptr;
        }
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, message, w_param, l_param);
    }
    return 0;
}

} // namespace gi

int APIENTRY wWinMain(_In_ HINSTANCE h_instance, _In_opt_ HINSTANCE h_prev_instance,
                      _In_ LPWSTR lp_cmd_line, _In_ int n_cmd_show) {
    UNREFERENCED_PARAMETER(h_prev_instance);
    UNREFERENCED_PARAMETER(lp_cmd_line);

    gi::g_hinst = h_instance;

    LoadStringW(h_instance, IDS_APP_TITLE, gi::g_title, 100);
    LoadStringW(h_instance, IDC_GENERICINJECTOR, gi::g_class_name, 100);

    gi::register_window_class(h_instance);
    if (!gi::init_instance(h_instance, n_cmd_show)) {
        return FALSE;
    }

    HACCEL accel = LoadAccelerators(h_instance, MAKEINTRESOURCE(IDC_GENERICINJECTOR));

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        if (!TranslateAccelerator(msg.hwnd, accel, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    gi::cleanup_scrambled_files();
    return static_cast<int>(msg.wParam);
}

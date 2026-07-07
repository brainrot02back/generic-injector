#include "framework.h"
#include "generic injector.h"

std::vector<ProcessEntry> g_processes;
InjectionSettings g_settings;
HIMAGELIST g_hImageList = nullptr;
HWND g_hTab = nullptr;
HWND g_hListView = nullptr;
HWND g_hFilterEdit = nullptr;
HWND g_hStatusBar = nullptr;
HWND g_hBtnRefresh = nullptr;
HWND g_hBtnInject = nullptr;
HWND g_hEditDllPath = nullptr;
HWND g_hBtnBrowse = nullptr;
HWND g_hComboMethod = nullptr;
HWND g_hChkScramble = nullptr;
HWND g_hChkClose = nullptr;
HWND g_hChkStealth = nullptr;
HWND g_hChkUnlink = nullptr;
HWND g_hGrpInjection = nullptr;
HWND g_hGrpOptions = nullptr;
HWND g_hLblDll = nullptr;
HWND g_hLblMethod = nullptr;
int g_sortColumn = 0;
bool g_sortAscending = true;
DWORD g_selectedPid = 0;

HINSTANCE hInst;
WCHAR szTitle[100];
WCHAR szWindowClass[100];

ATOM MyRegisterClass(HINSTANCE hInstance);
BOOL InitInstance(HINSTANCE, int);
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nCmdShow) {
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, 100);
    LoadStringW(hInstance, IDC_GENERICINJECTOR, szWindowClass, 100);
    MyRegisterClass(hInstance);

    if (!InitInstance(hInstance, nCmdShow)) {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_GENERICINJECTOR));
    MSG msg;

    while (GetMessage(&msg, nullptr, 0, 0)) {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    CleanupScrambledFiles();
    return (int)msg.wParam;
}

ATOM MyRegisterClass(HINSTANCE hInstance) {
    WNDCLASSEXW wcex;
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_GENERICINJECTOR));
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = nullptr;
    wcex.lpszClassName = szWindowClass;
    wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));
    return RegisterClassExW(&wcex);
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow) {
    hInst = hInstance;
    HWND hWnd = CreateWindowW(szWindowClass, L"Generic Injector", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, 0, 900, 600, nullptr, nullptr, hInstance, nullptr);
    if (!hWnd) {
        return FALSE;
    }
    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);
    return TRUE;
}

void SetupColumns(HWND hList) {
    LVCOLUMNW lvc;
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    
    lvc.iSubItem = 0; lvc.pszText = (LPWSTR)L"Process Name"; lvc.cx = 200; lvc.fmt = LVCFMT_LEFT;
    ListView_InsertColumn(hList, 0, &lvc);
    
    lvc.iSubItem = 1; lvc.pszText = (LPWSTR)L"PID"; lvc.cx = 60; lvc.fmt = LVCFMT_RIGHT;
    ListView_InsertColumn(hList, 1, &lvc);
    
    lvc.iSubItem = 2; lvc.pszText = (LPWSTR)L"CPU%"; lvc.cx = 60; lvc.fmt = LVCFMT_RIGHT;
    ListView_InsertColumn(hList, 2, &lvc);
    
    lvc.iSubItem = 3; lvc.pszText = (LPWSTR)L"RAM(MB)"; lvc.cx = 70; lvc.fmt = LVCFMT_RIGHT;
    ListView_InsertColumn(hList, 3, &lvc);
    
    lvc.iSubItem = 4; lvc.pszText = (LPWSTR)L"Arch"; lvc.cx = 50; lvc.fmt = LVCFMT_CENTER;
    ListView_InsertColumn(hList, 4, &lvc);
    
    lvc.iSubItem = 5; lvc.pszText = (LPWSTR)L"Window Title"; lvc.cx = 200; lvc.fmt = LVCFMT_LEFT;
    ListView_InsertColumn(hList, 5, &lvc);
    
    lvc.iSubItem = 6; lvc.pszText = (LPWSTR)L"Path"; lvc.cx = 300; lvc.fmt = LVCFMT_LEFT;
    ListView_InsertColumn(hList, 6, &lvc);
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE: {
        HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        
        g_hTab = CreateWindowW(WC_TABCONTROL, L"", WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE, 0, 0, 0, 0, hWnd, (HMENU)IDC_TAB_MAIN, hInst, nullptr);
        SendMessage(g_hTab, WM_SETFONT, (WPARAM)hFont, FALSE);
        
        TCITEMW tie;
        tie.mask = TCIF_TEXT | TCIF_IMAGE;
        tie.iImage = -1;
        tie.pszText = (LPWSTR)L"Processes";
        TabCtrl_InsertItem(g_hTab, 0, &tie);
        tie.pszText = (LPWSTR)L"Settings";
        TabCtrl_InsertItem(g_hTab, 1, &tie);

        g_hFilterEdit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, (HMENU)IDC_EDIT_FILTER, hInst, nullptr);
        SendMessage(g_hFilterEdit, WM_SETFONT, (WPARAM)hFont, FALSE);
        SendMessage(g_hFilterEdit, EM_SETCUEBANNER, FALSE, (LPARAM)L"Search Processes...");
        
        g_hBtnRefresh = CreateWindowW(L"BUTTON", L"Refresh", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hWnd, (HMENU)IDC_BTN_REFRESH, hInst, nullptr);
        SendMessage(g_hBtnRefresh, WM_SETFONT, (WPARAM)hFont, FALSE);

        g_hListView = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 0, 0, 0, 0, hWnd, (HMENU)IDC_PROCESS_LIST, hInst, nullptr);
        ListView_SetExtendedListViewStyle(g_hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
        SendMessage(g_hListView, WM_SETFONT, (WPARAM)hFont, FALSE);
        
        SetupColumns(g_hListView);

        CreateSettingsControls(hWnd, hInst);
        ShowSettingsControls(false);

        g_hStatusBar = CreateWindowW(STATUSCLASSNAME, L"", WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0, 0, 0, hWnd, (HMENU)IDC_STATUSBAR, hInst, nullptr);
        SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)L"Ready");

        g_hBtnInject = CreateWindowW(L"BUTTON", L"INJECT", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hWnd, (HMENU)IDC_BTN_INJECT, hInst, nullptr);
        SendMessage(g_hBtnInject, WM_SETFONT, (WPARAM)hFont, FALSE);

        LoadSettings(g_settings);
        ApplySettingsToControls(g_settings);

        EnumerateProcesses(g_processes);
        PopulateListView(g_hListView, g_processes, L"");

        SetTimer(hWnd, 1, 2000, nullptr);
        break;
    }
    case WM_SIZE: {
        int width = LOWORD(lParam);
        int height = HIWORD(lParam);
        
        int statusHeight = 22;
        SendMessage(g_hStatusBar, WM_SIZE, 0, 0);
        
        int injectBtnHeight = 40;
        int tabHeight = height - statusHeight - injectBtnHeight - 10;
        
        MoveWindow(g_hTab, 5, 5, width - 10, tabHeight, TRUE);
        MoveWindow(g_hBtnInject, width / 2 - 100, height - statusHeight - injectBtnHeight - 5, 200, injectBtnHeight, TRUE);
        
        RECT rcTab;
        GetClientRect(g_hTab, &rcTab);
        TabCtrl_AdjustRect(g_hTab, FALSE, &rcTab);
        
        int tabCX = rcTab.left + 5;
        int tabCY = rcTab.top + 5;
        int tabCW = rcTab.right - rcTab.left;
        int tabCH = rcTab.bottom - rcTab.top;

        MoveWindow(g_hFilterEdit, tabCX, tabCY, tabCW - 80, 22, TRUE);
        MoveWindow(g_hBtnRefresh, tabCX + tabCW - 75, tabCY, 75, 22, TRUE);
        MoveWindow(g_hListView, tabCX, tabCY + 27, tabCW, tabCH - 27, TRUE);
        
        break;
    }
    case WM_NOTIFY: {
        LPNMHDR lpnmh = (LPNMHDR)lParam;
        if (lpnmh->hwndFrom == g_hTab && lpnmh->code == TCN_SELCHANGE) {
            int sel = TabCtrl_GetCurSel(g_hTab);
            if (sel == 0) {
                ShowSettingsControls(false);
                ShowProcessControls(true);
            } else if (sel == 1) {
                ShowProcessControls(false);
                ShowSettingsControls(true);
            }
        } else if (lpnmh->hwndFrom == g_hListView) {
            if (lpnmh->code == LVN_ITEMCHANGED) {
                LPNMLISTVIEW pnmv = (LPNMLISTVIEW)lParam;
                if ((pnmv->uChanged & LVIF_STATE) && (pnmv->uNewState & LVIS_SELECTED)) {
                    g_selectedPid = (DWORD)pnmv->lParam;
                    wchar_t buf[256];
                    swprintf_s(buf, L"Selected PID: %d", g_selectedPid);
                    SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)buf);
                }
            } else if (lpnmh->code == LVN_COLUMNCLICK) {
                LPNMLISTVIEW pnmv = (LPNMLISTVIEW)lParam;
                if (g_sortColumn == pnmv->iSubItem) {
                    g_sortAscending = !g_sortAscending;
                } else {
                    g_sortColumn = pnmv->iSubItem;
                    g_sortAscending = true;
                }
                ListView_SortItemsEx(g_hListView, CompareListItems, (LPARAM)g_hListView);
            }
        }
        break;
    }
    case WM_COMMAND: {
        int wmId = LOWORD(wParam);
        if (wmId == IDC_BTN_REFRESH) {
            EnumerateProcesses(g_processes);
            wchar_t filter[256];
            GetWindowTextW(g_hFilterEdit, filter, 256);
            PopulateListView(g_hListView, g_processes, filter);
        } else if (wmId == IDC_EDIT_FILTER && HIWORD(wParam) == EN_CHANGE) {
            wchar_t filter[256];
            GetWindowTextW(g_hFilterEdit, filter, 256);
            PopulateListView(g_hListView, g_processes, filter);
        } else if (wmId == IDC_BTN_BROWSE) {
            OPENFILENAMEW ofn;
            wchar_t szFile[MAX_PATH] = {0};
            ZeroMemory(&ofn, sizeof(ofn));
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hWnd;
            ofn.lpstrFile = szFile;
            ofn.lpstrFile[0] = '\0';
            ofn.nMaxFile = sizeof(szFile);
            ofn.lpstrFilter = L"DLL Files (*.dll)\0*.dll\0All Files (*.*)\0*.*\0";
            ofn.nFilterIndex = 1;
            ofn.lpstrFileTitle = nullptr;
            ofn.nMaxFileTitle = 0;
            ofn.lpstrInitialDir = nullptr;
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
            if (GetOpenFileNameW(&ofn) == TRUE) {
                SetWindowTextW(g_hEditDllPath, ofn.lpstrFile);
            }
        } else if (wmId == IDC_BTN_INJECT) {
            UpdateSettingsFromControls(g_settings);
            SaveSettings(g_settings);
            
            if (g_selectedPid == 0) {
                MessageBoxW(hWnd, L"Please select a target process first.", L"Error", MB_ICONERROR);
                break;
            }
            if (g_settings.dllPath.empty() || GetFileAttributesW(g_settings.dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                MessageBoxW(hWnd, L"Please select a valid DLL file.", L"Error", MB_ICONERROR);
                TabCtrl_SetCurSel(g_hTab, 1);
                ShowProcessControls(false);
                ShowSettingsControls(true);
                break;
            }
            
            SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)L"Injecting...");
            
            InjectionResult result = PerformInjection(g_selectedPid, g_settings);
            
            SendMessage(g_hStatusBar, SB_SETTEXT, 0, (LPARAM)result.message.c_str());
            
            if (result.success && g_settings.closeOnInject) {
                PostMessage(hWnd, WM_CLOSE, 0, 0);
            } else if (!result.success) {
                MessageBoxW(hWnd, result.message.c_str(), L"Injection Failed", MB_ICONERROR);
            }
            
            CleanupScrambledFiles();
        } else {
            UpdateSettingsFromControls(g_settings);
            SaveSettings(g_settings);
        }
        break;
    }
    case WM_TIMER:
        if (wParam == 1 && TabCtrl_GetCurSel(g_hTab) == 0) {
            RefreshProcessStats(g_processes);
            
            int count = ListView_GetItemCount(g_hListView);
            for (int i = 0; i < count; i++) {
                LVITEMW lvi = {0};
                lvi.iItem = i;
                lvi.mask = LVIF_PARAM;
                ListView_GetItem(g_hListView, &lvi);
                DWORD pid = (DWORD)lvi.lParam;
                
                auto it = std::find_if(g_processes.begin(), g_processes.end(), [pid](const ProcessEntry& e) { return e.pid == pid; });
                if (it != g_processes.end()) {
                    wchar_t cpuBuf[32];
                    swprintf_s(cpuBuf, L"%.2f%%", it->cpuUsage);
                    ListView_SetItemText(g_hListView, i, 2, cpuBuf);
                    ListView_SetItemText(g_hListView, i, 3, const_cast<LPWSTR>(std::to_wstring(it->memoryUsageKB / 1024).c_str()));
                }
            }
        }
        break;
    case WM_DESTROY:
        if (g_hImageList) ImageList_Destroy(g_hImageList);
        KillTimer(hWnd, 1);
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

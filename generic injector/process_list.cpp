#include "framework.h"
#include "generic injector.h"

struct WindowEnumData {
    DWORD pid;
    std::wstring title;
};

BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
    WindowEnumData* data = reinterpret_cast<WindowEnumData*>(lParam);
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == data->pid && IsWindowVisible(hwnd)) {
        int length = GetWindowTextLengthW(hwnd);
        if (length > 0) {
            std::vector<wchar_t> buffer(length + 1);
            GetWindowTextW(hwnd, &buffer[0], length + 1);
            data->title = &buffer[0];
            return FALSE;
        }
    }
    return TRUE;
}

void EnumerateProcesses(std::vector<ProcessEntry>& entries) {
    entries.clear();
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == 0) continue;
                ProcessEntry entry;
                entry.pid = pe32.th32ProcessID;
                entry.name = pe32.szExeFile;
                entry.hIcon = nullptr;
                entry.memoryUsageKB = 0;
                entry.cpuUsage = 0.0;
                entry.isX64 = TRUE;
                entry.lastKernelTime = 0;
                entry.lastUserTime = 0;
                entry.lastSampleTime = 0;
                
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    wchar_t path[MAX_PATH];
                    DWORD size = MAX_PATH;
                    if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
                        entry.path = path;
                        ExtractIconExW(path, 0, nullptr, &entry.hIcon, 1);
                    }
                    
                    PROCESS_MEMORY_COUNTERS pmc;
                    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                        entry.memoryUsageKB = pmc.WorkingSetSize / 1024;
                    }
                    
                    BOOL isWow64 = FALSE;
                    if (IsWow64Process(hProcess, &isWow64)) {
                        entry.isX64 = !isWow64;
                    }
                    
                    FILETIME createTime, exitTime, kernelTime, userTime;
                    if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
                        ULARGE_INTEGER k, u;
                        k.LowPart = kernelTime.dwLowDateTime;
                        k.HighPart = kernelTime.dwHighDateTime;
                        u.LowPart = userTime.dwLowDateTime;
                        u.HighPart = userTime.dwHighDateTime;
                        entry.lastKernelTime = k.QuadPart;
                        entry.lastUserTime = u.QuadPart;
                        
                        FILETIME sysTime;
                        GetSystemTimeAsFileTime(&sysTime);
                        ULARGE_INTEGER s;
                        s.LowPart = sysTime.dwLowDateTime;
                        s.HighPart = sysTime.dwHighDateTime;
                        entry.lastSampleTime = s.QuadPart;
                    }
                    CloseHandle(hProcess);
                }
                
                WindowEnumData enumData;
                enumData.pid = entry.pid;
                EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&enumData));
                entry.windowTitle = enumData.title;
                
                entries.push_back(entry);
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
}

void PopulateListView(HWND hListView, std::vector<ProcessEntry>& entries, const std::wstring& filter) {
    SendMessage(hListView, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(hListView);
    
    if (g_hImageList) {
        ImageList_Destroy(g_hImageList);
    }
    g_hImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 1, 1);
    ListView_SetImageList(hListView, g_hImageList, LVSIL_SMALL);
    
    HICON defaultIcon = LoadIcon(nullptr, IDI_APPLICATION);
    
    std::wstring lowerFilter = filter;
    std::transform(lowerFilter.begin(), lowerFilter.end(), lowerFilter.begin(), ::towlower);
    
    int index = 0;
    for (const auto& entry : entries) {
        bool match = false;
        if (filter.empty()) {
            match = true;
        } else {
            std::wstring lowerName = entry.name;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
            std::wstring lowerTitle = entry.windowTitle;
            std::transform(lowerTitle.begin(), lowerTitle.end(), lowerTitle.begin(), ::towlower);
            std::wstring pidStr = std::to_wstring(entry.pid);
            
            if (lowerName.find(lowerFilter) != std::wstring::npos ||
                lowerTitle.find(lowerFilter) != std::wstring::npos ||
                pidStr.find(lowerFilter) != std::wstring::npos) {
                match = true;
            }
        }
        
        if (match) {
            HICON icon = entry.hIcon ? entry.hIcon : defaultIcon;
            int iconIndex = ImageList_AddIcon(g_hImageList, icon);
            
            LVITEMW lvI = {0};
            lvI.pszText = const_cast<LPWSTR>(entry.name.c_str());
            lvI.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
            lvI.iItem = index;
            lvI.iImage = iconIndex;
            lvI.iSubItem = 0;
            lvI.lParam = entry.pid;
            ListView_InsertItem(hListView, &lvI);
            
            ListView_SetItemText(hListView, index, 1, const_cast<LPWSTR>(std::to_wstring(entry.pid).c_str()));
            
            wchar_t cpuBuf[32];
            swprintf_s(cpuBuf, L"%.2f%%", entry.cpuUsage);
            ListView_SetItemText(hListView, index, 2, cpuBuf);
            
            ListView_SetItemText(hListView, index, 3, const_cast<LPWSTR>(std::to_wstring(entry.memoryUsageKB / 1024).c_str()));
            
            ListView_SetItemText(hListView, index, 4, const_cast<LPWSTR>(entry.isX64 ? L"x64" : L"x86"));
            ListView_SetItemText(hListView, index, 5, const_cast<LPWSTR>(entry.windowTitle.c_str()));
            ListView_SetItemText(hListView, index, 6, const_cast<LPWSTR>(entry.path.c_str()));
            
            index++;
        }
    }
    
    SendMessage(hListView, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(hListView, nullptr, TRUE);
}

void RefreshProcessStats(std::vector<ProcessEntry>& entries) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    int numCPUs = sysInfo.dwNumberOfProcessors;
    
    FILETIME sysTime;
    GetSystemTimeAsFileTime(&sysTime);
    ULARGE_INTEGER s;
    s.LowPart = sysTime.dwLowDateTime;
    s.HighPart = sysTime.dwHighDateTime;
    ULONGLONG currentSampleTime = s.QuadPart;
    
    for (auto& entry : entries) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.pid);
        if (hProcess) {
            PROCESS_MEMORY_COUNTERS pmc;
            if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                entry.memoryUsageKB = pmc.WorkingSetSize / 1024;
            }
            
            FILETIME createTime, exitTime, kernelTime, userTime;
            if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
                ULARGE_INTEGER k, u;
                k.LowPart = kernelTime.dwLowDateTime;
                k.HighPart = kernelTime.dwHighDateTime;
                u.LowPart = userTime.dwLowDateTime;
                u.HighPart = userTime.dwHighDateTime;
                
                ULONGLONG kernelDelta = k.QuadPart - entry.lastKernelTime;
                ULONGLONG userDelta = u.QuadPart - entry.lastUserTime;
                ULONGLONG timeDelta = currentSampleTime - entry.lastSampleTime;
                
                if (timeDelta > 0) {
                    double cpu = (double)(kernelDelta + userDelta) / timeDelta * 100.0 / numCPUs;
                    if (cpu < 0.0) cpu = 0.0;
                    if (cpu > 100.0) cpu = 100.0;
                    entry.cpuUsage = cpu;
                }
                
                entry.lastKernelTime = k.QuadPart;
                entry.lastUserTime = u.QuadPart;
                entry.lastSampleTime = currentSampleTime;
            }
            CloseHandle(hProcess);
        }
    }
}

int CALLBACK CompareListItems(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) {
    HWND hListView = reinterpret_cast<HWND>(lParamSort);
    
    LVFINDINFO findInfo1;
    findInfo1.flags = LVFI_PARAM;
    findInfo1.lParam = lParam1;
    int index1 = ListView_FindItem(hListView, -1, &findInfo1);
    
    LVFINDINFO findInfo2;
    findInfo2.flags = LVFI_PARAM;
    findInfo2.lParam = lParam2;
    int index2 = ListView_FindItem(hListView, -1, &findInfo2);
    
    wchar_t buf1[256] = {0};
    wchar_t buf2[256] = {0};
    ListView_GetItemText(hListView, index1, g_sortColumn, buf1, 256);
    ListView_GetItemText(hListView, index2, g_sortColumn, buf2, 256);
    
    int result = 0;
    if (g_sortColumn == 1 || g_sortColumn == 2 || g_sortColumn == 3) {
        double val1 = _wtof(buf1);
        double val2 = _wtof(buf2);
        if (val1 < val2) result = -1;
        else if (val1 > val2) result = 1;
    } else {
        result = _wcsicmp(buf1, buf2);
    }
    
    return g_sortAscending ? result : -result;
}

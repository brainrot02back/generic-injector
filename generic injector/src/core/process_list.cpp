#include "api.h"

namespace gi {

struct window_enum_data {
    DWORD        pid = 0;
    std::wstring title;
};

static BOOL CALLBACK enum_windows_callback(HWND hwnd, LPARAM l_param) {
    auto* data = reinterpret_cast<window_enum_data*>(l_param);
    if (!data) return TRUE;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != data->pid || !IsWindowVisible(hwnd)) return TRUE;

    const int length = GetWindowTextLengthW(hwnd);
    if (length <= 0) return TRUE;

    std::vector<wchar_t> buffer(length + 1);
    GetWindowTextW(hwnd, buffer.data(), length + 1);
    data->title = buffer.data();
    return FALSE;
}

void enumerate_processes(std::vector<process_entry>& entries) {
    entries.clear();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(pe32);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == 0) continue;

            process_entry entry;
            entry.pid  = pe32.th32ProcessID;
            entry.name = pe32.szExeFile;

            HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.pid);
            if (process) {
                wchar_t path[MAX_PATH] = {};
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageNameW(process, 0, path, &size)) {
                    entry.path = path;
                    ExtractIconExW(path, 0, nullptr, &entry.icon, 1);
                }

                PROCESS_MEMORY_COUNTERS pmc{};
                if (GetProcessMemoryInfo(process, &pmc, sizeof(pmc))) {
                    entry.memory_usage_kb = pmc.WorkingSetSize / 1024;
                }

                BOOL is_wow64 = FALSE;
                if (IsWow64Process(process, &is_wow64)) {
                    entry.is_x64 = !is_wow64;
                }

                FILETIME create_time{}, exit_time{}, kernel_time{}, user_time{};
                if (GetProcessTimes(process, &create_time, &exit_time, &kernel_time, &user_time)) {
                    ULARGE_INTEGER k, u, s;
                    k.LowPart = kernel_time.dwLowDateTime;
                    k.HighPart = kernel_time.dwHighDateTime;
                    u.LowPart = user_time.dwLowDateTime;
                    u.HighPart = user_time.dwHighDateTime;

                    FILETIME sys_time;
                    GetSystemTimeAsFileTime(&sys_time);
                    s.LowPart = sys_time.dwLowDateTime;
                    s.HighPart = sys_time.dwHighDateTime;

                    entry.last_kernel_time  = k.QuadPart;
                    entry.last_user_time    = u.QuadPart;
                    entry.last_sample_time  = s.QuadPart;
                }

                CloseHandle(process);
            }

            window_enum_data enum_data;
            enum_data.pid = entry.pid;
            EnumWindows(enum_windows_callback, reinterpret_cast<LPARAM>(&enum_data));
            entry.window_title = enum_data.title;

            entries.push_back(std::move(entry));
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
}

void populate_list_view(HWND list_view, std::vector<process_entry>& entries, const std::wstring& filter) {
    SendMessage(list_view, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(list_view);

    if (g_image_list) {
        ImageList_Destroy(g_image_list);
    }
    g_image_list = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 1, 1);
    ListView_SetImageList(list_view, g_image_list, LVSIL_SMALL);

    HICON default_icon = LoadIcon(nullptr, IDI_APPLICATION);

    std::wstring lower_filter = filter;
    std::transform(lower_filter.begin(), lower_filter.end(), lower_filter.begin(), ::towlower);

    int index = 0;
    for (const auto& entry : entries) {
        bool match = lower_filter.empty();
        if (!match) {
            std::wstring lower_name  = entry.name;
            std::wstring lower_title = entry.window_title;
            std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::towlower);
            std::transform(lower_title.begin(), lower_title.end(), lower_title.begin(), ::towlower);

            const std::wstring pid_str = std::to_wstring(entry.pid);
            match = lower_name.find(lower_filter)  != std::wstring::npos ||
                    lower_title.find(lower_filter) != std::wstring::npos ||
                    pid_str.find(lower_filter)      != std::wstring::npos;
        }
        if (!match) continue;

        const int icon_index = ImageList_AddIcon(g_image_list, entry.icon ? entry.icon : default_icon);

        LVITEMW lvi{};
        lvi.mask     = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
        lvi.iItem    = index;
        lvi.iSubItem = 0;
        lvi.iImage   = icon_index;
        lvi.pszText  = const_cast<LPWSTR>(entry.name.c_str());
        lvi.lParam   = entry.pid;
        ListView_InsertItem(list_view, &lvi);

        const std::wstring pid_text    = std::to_wstring(entry.pid);
        const std::wstring memory_text = std::to_wstring(entry.memory_usage_kb / 1024);
        wchar_t cpu_buf[32];

        swprintf_s(cpu_buf, L"%.2f%%", entry.cpu_usage);

        ListView_SetItemText(list_view, index, 1, const_cast<LPWSTR>(pid_text.c_str()));
        ListView_SetItemText(list_view, index, 2, cpu_buf);
        ListView_SetItemText(list_view, index, 3, const_cast<LPWSTR>(memory_text.c_str()));
        ListView_SetItemText(list_view, index, 4, const_cast<LPWSTR>(entry.is_x64 ? L"x64" : L"x86"));
        ListView_SetItemText(list_view, index, 5, const_cast<LPWSTR>(entry.window_title.c_str()));
        ListView_SetItemText(list_view, index, 6, const_cast<LPWSTR>(entry.path.c_str()));

        ++index;
    }

    SendMessage(list_view, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(list_view, nullptr, TRUE);
}

void refresh_process_stats(std::vector<process_entry>& entries) {
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    const int num_cpus = sys_info.dwNumberOfProcessors;
    if (num_cpus <= 0) return;

    FILETIME sys_time;
    GetSystemTimeAsFileTime(&sys_time);
    ULARGE_INTEGER s;
    s.LowPart  = sys_time.dwLowDateTime;
    s.HighPart = sys_time.dwHighDateTime;
    const ULONGLONG current_sample_time = s.QuadPart;

    for (auto& entry : entries) {
        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.pid);
        if (!process) continue;

        PROCESS_MEMORY_COUNTERS pmc{};
        if (GetProcessMemoryInfo(process, &pmc, sizeof(pmc))) {
            entry.memory_usage_kb = pmc.WorkingSetSize / 1024;
        }

        FILETIME create_time{}, exit_time{}, kernel_time{}, user_time{};
        if (GetProcessTimes(process, &create_time, &exit_time, &kernel_time, &user_time)) {
            ULARGE_INTEGER k, u;
            k.LowPart  = kernel_time.dwLowDateTime;
            k.HighPart = kernel_time.dwHighDateTime;
            u.LowPart  = user_time.dwLowDateTime;
            u.HighPart = user_time.dwHighDateTime;

            const ULONGLONG kernel_delta = k.QuadPart - entry.last_kernel_time;
            const ULONGLONG user_delta   = u.QuadPart - entry.last_user_time;
            const ULONGLONG time_delta   = current_sample_time - entry.last_sample_time;

            if (time_delta > 0 && entry.last_sample_time != 0) {
                double cpu = static_cast<double>(kernel_delta + user_delta) / time_delta * 100.0 / num_cpus;
                cpu = std::clamp(cpu, 0.0, 100.0);
                entry.cpu_usage = cpu;
            }

            entry.last_kernel_time = k.QuadPart;
            entry.last_user_time   = u.QuadPart;
            entry.last_sample_time = current_sample_time;
        }

        CloseHandle(process);
    }
}

int CALLBACK compare_list_items(LPARAM l_param1, LPARAM l_param2, LPARAM l_param_sort) {
    auto list_view = reinterpret_cast<HWND>(l_param_sort);
    if (!list_view) return 0;

    LVFINDINFO find1{};
    find1.flags   = LVFI_PARAM;
    find1.lParam = l_param1;
    const int index1 = ListView_FindItem(list_view, -1, &find1);

    LVFINDINFO find2{};
    find2.flags   = LVFI_PARAM;
    find2.lParam = l_param2;
    const int index2 = ListView_FindItem(list_view, -1, &find2);

    wchar_t buf1[256] = {};
    wchar_t buf2[256] = {};
    ListView_GetItemText(list_view, index1, g_sort_column, buf1, 256);
    ListView_GetItemText(list_view, index2, g_sort_column, buf2, 256);

    int result;
    if (g_sort_column == 1 || g_sort_column == 2 || g_sort_column == 3) {
        const double val1 = _wtof(buf1);
        const double val2 = _wtof(buf2);
        result = (val1 < val2) ? -1 : (val1 > val2 ? 1 : 0);
    } else {
        result = _wcsicmp(buf1, buf2);
    }

    return g_sort_ascending ? result : -result;
}

} // namespace gi

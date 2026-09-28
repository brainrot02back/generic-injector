#pragma once

#include "framework.h"

namespace gi {

struct process_entry {
    DWORD        pid = 0;
    std::wstring name;
    std::wstring path;
    std::wstring window_title;
    HICON        icon = nullptr;
    SIZE_T       memory_usage_kb = 0;
    double       cpu_usage = 0.0;
    bool         is_x64 = true;
    ULONGLONG    last_kernel_time = 0;
    ULONGLONG    last_user_time = 0;
    ULONGLONG    last_sample_time = 0;
};

enum class injection_method {
    load_library = 0,
    manual_map,
    nt_create_thread_ex,
    thread_hijack,
};

struct injection_settings {
    std::wstring   dll_path;
    injection_method method = injection_method::load_library;
    bool           scramble_dll = false;
    bool           close_on_inject = false;
    bool           stealth_mode = false;
    bool           unlink_from_peb = false;
};

struct injection_result {
    bool         success = false;
    std::wstring message;
};

} // namespace gi

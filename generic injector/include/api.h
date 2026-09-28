#pragma once

#include "framework.h"
#include "resource_ids.h"
#include "types.h"
#include "globals.h"

namespace gi {

// process_list
void enumerate_processes(std::vector<process_entry>& entries);
void populate_list_view(HWND list_view, std::vector<process_entry>& entries, const std::wstring& filter);
void refresh_process_stats(std::vector<process_entry>& entries);
int  CALLBACK compare_list_items(LPARAM l_param1, LPARAM l_param2, LPARAM l_param_sort);

// injection
injection_result inject_load_library(DWORD pid, const std::wstring& dll_path);
injection_result inject_manual_map(DWORD pid, const std::wstring& dll_path, bool erase_headers);
injection_result inject_nt_create_thread_ex(DWORD pid, const std::wstring& dll_path);
injection_result inject_thread_hijack(DWORD pid, const std::wstring& dll_path);
injection_result perform_injection(DWORD pid, const injection_settings& settings);

// scramble
std::wstring scramble_dll(const std::wstring& original_path);
void         cleanup_scrambled_files();

// settings/ui helpers
std::wstring get_settings_path();
void         save_settings(const injection_settings& settings);
void         load_settings(injection_settings& settings);
void         create_settings_controls(HWND parent, HINSTANCE inst);
void         show_settings_controls(bool show);
void         show_process_controls(bool show);
void         update_settings_from_controls(injection_settings& settings);
void         apply_settings_to_controls(const injection_settings& settings);

} // namespace gi

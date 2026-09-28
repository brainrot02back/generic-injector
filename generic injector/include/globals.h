#pragma once

#include "types.h"

namespace gi {

inline std::vector<process_entry> g_processes;
inline injection_settings          g_settings;

inline HIMAGELIST g_image_list = nullptr;
inline HWND       g_tab        = nullptr;
inline HWND       g_list_view  = nullptr;
inline HWND       g_filter_edit= nullptr;
inline HWND       g_status_bar = nullptr;
inline HWND       g_btn_refresh= nullptr;
inline HWND       g_btn_inject = nullptr;
inline HWND       g_edit_dll_path = nullptr;
inline HWND       g_btn_browse    = nullptr;
inline HWND       g_combo_method  = nullptr;
inline HWND       g_chk_scramble  = nullptr;
inline HWND       g_chk_close     = nullptr;
inline HWND       g_chk_stealth   = nullptr;
inline HWND       g_chk_unlink    = nullptr;
inline HWND       g_grp_injection = nullptr;
inline HWND       g_grp_options   = nullptr;
inline HWND       g_lbl_dll       = nullptr;
inline HWND       g_lbl_method    = nullptr;

inline int  g_sort_column   = 0;
inline bool g_sort_ascending = true;
inline DWORD g_selected_pid  = 0;

inline HINSTANCE g_hinst = nullptr;
inline WCHAR     g_title[100]  = {};
inline WCHAR     g_class_name[100] = {};

inline std::vector<std::wstring> g_scrambled_files;

} // namespace gi

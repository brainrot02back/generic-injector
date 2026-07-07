#pragma once

#include "framework.h"
#include "Resource.h"

struct ProcessEntry {
    DWORD pid;
    std::wstring name;
    std::wstring path;
    std::wstring windowTitle;
    HICON hIcon;
    SIZE_T memoryUsageKB;
    double cpuUsage;
    BOOL isX64;
    ULONGLONG lastKernelTime;
    ULONGLONG lastUserTime;
    ULONGLONG lastSampleTime;
};

enum class InjectionMethod {
    LoadLibrary = 0,
    ManualMap,
    NtCreateThreadEx,
    ThreadHijack
};

struct InjectionSettings {
    std::wstring dllPath;
    InjectionMethod method;
    bool scrambleDll;
    bool closeOnInject;
    bool stealthMode;
    bool unlinkFromPeb;
};

struct InjectionResult {
    bool success;
    std::wstring message;
};

void EnumerateProcesses(std::vector<ProcessEntry>& entries);
void PopulateListView(HWND hListView, std::vector<ProcessEntry>& entries, const std::wstring& filter);
void RefreshProcessStats(std::vector<ProcessEntry>& entries);
int CALLBACK CompareListItems(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);

InjectionResult InjectLoadLibrary(DWORD pid, const std::wstring& dllPath);
InjectionResult InjectManualMap(DWORD pid, const std::wstring& dllPath, bool eraseHeaders);
InjectionResult InjectNtCreateThreadEx(DWORD pid, const std::wstring& dllPath);
InjectionResult InjectThreadHijack(DWORD pid, const std::wstring& dllPath);
InjectionResult PerformInjection(DWORD pid, const InjectionSettings& settings);

std::wstring ScrambleDll(const std::wstring& originalPath);
void CleanupScrambledFiles();

void SaveSettings(const InjectionSettings& settings);
void LoadSettings(InjectionSettings& settings);
void CreateSettingsControls(HWND hParent, HINSTANCE hInst);
void ShowSettingsControls(bool show);
void ShowProcessControls(bool show);
void UpdateSettingsFromControls(InjectionSettings& settings);
void ApplySettingsToControls(const InjectionSettings& settings);

extern std::vector<ProcessEntry> g_processes;
extern InjectionSettings g_settings;
extern HIMAGELIST g_hImageList;
extern HWND g_hTab;
extern HWND g_hListView;
extern HWND g_hFilterEdit;
extern HWND g_hStatusBar;
extern HWND g_hBtnRefresh;
extern HWND g_hBtnInject;
extern HWND g_hEditDllPath;
extern HWND g_hBtnBrowse;
extern HWND g_hComboMethod;
extern HWND g_hChkScramble;
extern HWND g_hChkClose;
extern HWND g_hChkStealth;
extern HWND g_hChkUnlink;
extern HWND g_hGrpInjection;
extern HWND g_hGrpOptions;
extern HWND g_hLblDll;
extern HWND g_hLblMethod;
extern int g_sortColumn;
extern bool g_sortAscending;
extern DWORD g_selectedPid;

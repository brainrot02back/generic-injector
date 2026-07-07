#include "framework.h"
#include "generic injector.h"

static std::vector<std::wstring> g_scrambledFiles;

std::wstring ScrambleDll(const std::wstring& originalPath) {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    
    std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<> dis(0, 35);
    
    std::wstring randomName;
    for (int i = 0; i < 8; ++i) {
        int v = dis(gen);
        if (v < 10) randomName += (wchar_t)(L'0' + v);
        else randomName += (wchar_t)(L'a' + (v - 10));
    }
    randomName += L".dll";
    
    std::wstring targetPath = std::wstring(tempPath) + randomName;
    
    if (!CopyFileW(originalPath.c_str(), targetPath.c_str(), FALSE)) {
        return originalPath;
    }
    
    HANDLE hFile = CreateFileW(targetPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return originalPath;
    }
    
    DWORD fileSize = GetFileSize(hFile, nullptr);
    std::vector<BYTE> buffer(fileSize);
    DWORD bytesRead;
    ReadFile(hFile, buffer.data(), fileSize, &bytesRead, nullptr);
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer.data();
    if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(buffer.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
            ntHeaders->FileHeader.TimeDateStamp = 0;
            
            if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size > 0) {
                ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
                ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
            }
            
            PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
            for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
                for (int j = 0; j < 8; ++j) {
                    int v = dis(gen);
                    if (v < 10) sectionHeader[i].Name[j] = '0' + v;
                    else sectionHeader[i].Name[j] = 'a' + (v - 10);
                }
            }
            
            SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
            DWORD bytesWritten;
            WriteFile(hFile, buffer.data(), fileSize, &bytesWritten, nullptr);
        }
    }
    
    CloseHandle(hFile);
    g_scrambledFiles.push_back(targetPath);
    return targetPath;
}

void CleanupScrambledFiles() {
    for (const auto& path : g_scrambledFiles) {
        DeleteFileW(path.c_str());
    }
    g_scrambledFiles.clear();
}

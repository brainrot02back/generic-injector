#include "api.h"

namespace gi {

std::wstring scramble_dll(const std::wstring& original_path) {
    wchar_t temp_path[MAX_PATH];
    GetTempPathW(MAX_PATH, temp_path);

    std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<> dis(0, 35);

    std::wstring random_name;
    for (int i = 0; i < 8; ++i) {
        const int v = dis(gen);
        random_name += (v < 10) ? static_cast<wchar_t>(L'0' + v)
                               : static_cast<wchar_t>(L'a' + (v - 10));
    }
    random_name += L".dll";

    const std::wstring target_path = std::wstring(temp_path) + random_name;

    if (!CopyFileW(original_path.c_str(), target_path.c_str(), FALSE)) {
        return original_path;
    }

    HANDLE file = CreateFileW(target_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return original_path;
    }

    const DWORD file_size = GetFileSize(file, nullptr);
    std::vector<BYTE> buffer(file_size);
    DWORD bytes_read = 0;
    ReadFile(file, buffer.data(), file_size, &bytes_read, nullptr);

    auto* dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());
    if (dos_header->e_magic == IMAGE_DOS_SIGNATURE) {
        auto* nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer.data() + dos_header->e_lfanew);
        if (nt_headers->Signature == IMAGE_NT_SIGNATURE) {
            nt_headers->FileHeader.TimeDateStamp = 0;

            if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size > 0) {
                nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
                nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
            }

            auto* section_header = IMAGE_FIRST_SECTION(nt_headers);
            for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
                for (int j = 0; j < 8; ++j) {
                    const int v = dis(gen);
                    section_header[i].Name[j] = (v < 10) ? static_cast<CHAR>('0' + v)
                                                        : static_cast<CHAR>('a' + (v - 10));
                }
            }

            SetFilePointer(file, 0, nullptr, FILE_BEGIN);
            DWORD bytes_written = 0;
            WriteFile(file, buffer.data(), file_size, &bytes_written, nullptr);
        }
    }

    CloseHandle(file);
    g_scrambled_files.push_back(target_path);
    return target_path;
}

void cleanup_scrambled_files() {
    for (const auto& path : g_scrambled_files) {
        DeleteFileW(path.c_str());
    }
    g_scrambled_files.clear();
}

} // namespace gi

#include "api.h"

#include <winternl.h>

namespace gi {

using nt_create_thread_ex_fn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID,
                                                  PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
using load_library_a_fn       = HMODULE(WINAPI*)(LPCSTR);
using get_proc_address_fn     = FARPROC(WINAPI*)(HMODULE, LPCSTR);
using dll_main_fn             = BOOL(WINAPI*)(HMODULE, DWORD, LPVOID);

struct manual_map_data {
    load_library_a_fn   p_load_library_a;
    get_proc_address_fn p_get_proc_address;
    HMODULE             h_module;
    BOOL                success;
};

#pragma runtime_checks("", off)
static void __stdcall shellcode_manual_map(manual_map_data* data) {
    if (!data) return;

    BYTE* base = (BYTE*)data->h_module;
    auto* dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    auto* nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos_header->e_lfanew);

    auto* relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
        base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    const DWORD delta = (DWORD)((ULONG_PTR)base - nt_headers->OptionalHeader.ImageBase);

    while (relocation->VirtualAddress) {
        PWORD reloc_info = (PWORD)(relocation + 1);
        const int count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        for (int i = 0; i < count; ++i, ++reloc_info) {
            const WORD type = (WORD)(*reloc_info >> 12);
            const WORD rva  = (WORD)(*reloc_info & 0xFFF);
            if (type == IMAGE_REL_BASED_DIR64) {
                *(ULONG_PTR*)(base + relocation->VirtualAddress + rva) += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                *(DWORD*)(base + relocation->VirtualAddress + rva) += delta;
            }
        }
        relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>((BYTE*)relocation + relocation->SizeOfBlock);
    }

    auto* import_desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        while (import_desc->Name) {
            const char* module_name = (const char*)(base + import_desc->Name);
            HMODULE h_module = data->p_load_library_a(module_name);

            auto* thunk_ref = reinterpret_cast<PIMAGE_THUNK_DATA>(base + import_desc->OriginalFirstThunk);
            auto* func_ref  = reinterpret_cast<PIMAGE_THUNK_DATA>(base + import_desc->FirstThunk);
            if (!thunk_ref) thunk_ref = func_ref;

            while (thunk_ref->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(thunk_ref->u1.Ordinal)) {
                    func_ref->u1.Function = (ULONG_PTR)data->p_get_proc_address(
                        h_module, (LPCSTR)IMAGE_ORDINAL(thunk_ref->u1.Ordinal));
                } else {
                    auto* import_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(base + thunk_ref->u1.AddressOfData);
                    func_ref->u1.Function = (ULONG_PTR)data->p_get_proc_address(
                        h_module, (LPCSTR)import_name->Name);
                }
                ++thunk_ref;
                ++func_ref;
            }
            ++import_desc;
        }
    }

    if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* tls = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(
            base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
        if (callback) {
            while (*callback) {
                (*callback)((PVOID)base, DLL_PROCESS_ATTACH, nullptr);
                ++callback;
            }
        }
    }

    if (nt_headers->OptionalHeader.AddressOfEntryPoint) {
        auto dll_main = reinterpret_cast<dll_main_fn>(base + nt_headers->OptionalHeader.AddressOfEntryPoint);
        dll_main((HMODULE)base, DLL_PROCESS_ATTACH, nullptr);
    }

    data->success = TRUE;
}
static void shellcode_manual_map_end() {}
#pragma runtime_checks("", restore)

static injection_result fail(std::wstring message) {
    return { false, std::move(message) };
}

injection_result inject_load_library(DWORD pid, const std::wstring& dll_path) {
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!process) return fail(L"Failed to open process.");

    const SIZE_T path_size = (dll_path.length() + 1) * sizeof(wchar_t);
    LPVOID remote_mem = VirtualAllocEx(process, nullptr, path_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_mem) {
        CloseHandle(process);
        return fail(L"Failed to allocate memory in target process.");
    }

    if (!WriteProcessMemory(process, remote_mem, dll_path.c_str(), path_size, nullptr)) {
        VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
        CloseHandle(process);
        return fail(L"Failed to write DLL path to target process.");
    }

    auto p_load_library = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");

    HANDLE thread = CreateRemoteThread(process, nullptr, 0,
                                       (LPTHREAD_START_ROUTINE)p_load_library, remote_mem, 0, nullptr);
    if (!thread) {
        VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
        CloseHandle(process);
        return fail(L"Failed to create remote thread.");
    }

    WaitForSingleObject(thread, 5000);

    DWORD exit_code = 0;
    GetExitCodeThread(thread, &exit_code);

    CloseHandle(thread);
    VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
    CloseHandle(process);

    if (exit_code != 0) return { true, L"Successfully injected using LoadLibraryW." };
    return fail(L"Thread returned zero.");
}

injection_result inject_nt_create_thread_ex(DWORD pid, const std::wstring& dll_path) {
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!process) return fail(L"Failed to open process.");

    const SIZE_T path_size = (dll_path.length() + 1) * sizeof(wchar_t);
    LPVOID remote_mem = VirtualAllocEx(process, nullptr, path_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_mem) {
        CloseHandle(process);
        return fail(L"Failed to allocate memory in target process.");
    }

    if (!WriteProcessMemory(process, remote_mem, dll_path.c_str(), path_size, nullptr)) {
        VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
        CloseHandle(process);
        return fail(L"Failed to write DLL path to target process.");
    }

    auto p_load_library = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");

    auto nt_create_thread_ex = reinterpret_cast<nt_create_thread_ex_fn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx"));
    if (!nt_create_thread_ex) {
        VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
        CloseHandle(process);
        return fail(L"Failed to find NtCreateThreadEx.");
    }

    HANDLE thread = nullptr;
    const NTSTATUS status = nt_create_thread_ex(&thread, GENERIC_ALL, nullptr, process,
                                                (PVOID)p_load_library, remote_mem,
                                                0, 0, 0, 0, nullptr);

    VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
    CloseHandle(process);

    if (status == 0 && thread) {
        WaitForSingleObject(thread, 5000);
        CloseHandle(thread);
        return { true, L"Successfully injected using NtCreateThreadEx." };
    }
    return fail(L"NtCreateThreadEx failed.");
}

injection_result inject_manual_map(DWORD pid, const std::wstring& dll_path, bool erase_headers) {
    HANDLE file = CreateFileW(dll_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return fail(L"Failed to open DLL file.");

    const DWORD file_size = GetFileSize(file, nullptr);
    std::vector<BYTE> buffer(file_size);
    DWORD bytes_read = 0;
    ReadFile(file, buffer.data(), file_size, &bytes_read, nullptr);
    CloseHandle(file);

    auto* dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return fail(L"Invalid DOS signature.");

    auto* nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer.data() + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return fail(L"Invalid NT signature.");

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!process) return fail(L"Failed to open process.");

    LPVOID target_base = VirtualAllocEx(process, nullptr, nt_headers->OptionalHeader.SizeOfImage,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!target_base) {
        CloseHandle(process);
        return fail(L"Failed to allocate memory for image.");
    }

    WriteProcessMemory(process, target_base, buffer.data(), nt_headers->OptionalHeader.SizeOfHeaders, nullptr);

    auto* section_header = IMAGE_FIRST_SECTION(nt_headers);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
        if (section_header[i].SizeOfRawData) {
            WriteProcessMemory(process,
                               (BYTE*)target_base + section_header[i].VirtualAddress,
                               buffer.data() + section_header[i].PointerToRawData,
                               section_header[i].SizeOfRawData, nullptr);
        }
    }

    manual_map_data data{};
    data.p_load_library_a = (load_library_a_fn)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");
    data.p_get_proc_address = (get_proc_address_fn)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetProcAddress");
    data.h_module = (HMODULE)target_base;
    data.success  = FALSE;

    LPVOID remote_data = VirtualAllocEx(process, nullptr, sizeof(data), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(process, remote_data, &data, sizeof(data), nullptr);

    const SIZE_T shellcode_size = (BYTE*)shellcode_manual_map_end - (BYTE*)shellcode_manual_map;
    LPVOID shellcode = VirtualAllocEx(process, nullptr, shellcode_size,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(process, shellcode, (const void*)shellcode_manual_map, shellcode_size, nullptr);

    injection_result result;
    HANDLE thread = CreateRemoteThread(process, nullptr, 0,
                                       (LPTHREAD_START_ROUTINE)shellcode, remote_data, 0, nullptr);
    if (thread) {
        WaitForSingleObject(thread, 10000);

        manual_map_data result_back{};
        ReadProcessMemory(process, remote_data, &result_back, sizeof(result_back), nullptr);

        if (result_back.success) {
            result = { true, L"Successfully manually mapped DLL." };

            if (erase_headers) {
                const std::vector<BYTE> empty_headers(nt_headers->OptionalHeader.SizeOfHeaders, 0);
                WriteProcessMemory(process, target_base, empty_headers.data(), empty_headers.size(), nullptr);
            }
        } else {
            result = fail(L"Manual mapping failed during execution.");
        }
        CloseHandle(thread);
    } else {
        result = fail(L"Failed to create thread for manual mapping.");
    }

    VirtualFreeEx(process, remote_data, 0, MEM_RELEASE);
    VirtualFreeEx(process, shellcode, 0, MEM_RELEASE);
    CloseHandle(process);

    return result;
}

injection_result inject_thread_hijack(DWORD pid, const std::wstring& dll_path) {
#if !defined(_M_X64) && !defined(_M_AMD64)
    UNREFERENCED_PARAMETER(pid);
    UNREFERENCED_PARAMETER(dll_path);
    return fail(L"Thread hijack requires a 64-bit build (x86 is unsupported).");
#else
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!process) return fail(L"Failed to open process.");

    const SIZE_T path_size = (dll_path.length() + 1) * sizeof(wchar_t);
    LPVOID remote_mem = VirtualAllocEx(process, nullptr, path_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_mem) {
        CloseHandle(process);
        return fail(L"Failed to allocate memory in target process.");
    }
    WriteProcessMemory(process, remote_mem, dll_path.c_str(), path_size, nullptr);

    auto p_load_library = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");

    DWORD thread_id = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te32{};
    te32.dwSize = sizeof(te32);
    if (snapshot != INVALID_HANDLE_VALUE) {
        if (Thread32First(snapshot, &te32)) {
            do {
                if (te32.th32OwnerProcessID == pid) {
                    thread_id = te32.th32ThreadID;
                    break;
                }
            } while (Thread32Next(snapshot, &te32));
        }
        CloseHandle(snapshot);
    }

    if (!thread_id) {
        VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
        CloseHandle(process);
        return fail(L"Failed to find thread in target process.");
    }

    HANDLE thread = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
    if (!thread) {
        VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
        CloseHandle(process);
        return fail(L"Failed to open target thread.");
    }

    SuspendThread(thread);

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(thread, &ctx);

    BYTE shellcode[] = {
        0x50,                                                              // push rax
        0x9C,                                                              // pushfq
        0x51,                                                              // push rcx
        0x52,                                                              // push rdx
        0x41, 0x50,                                                        // push r8
        0x41, 0x51,                                                        // push r9
        0x41, 0x52,                                                        // push r10
        0x41, 0x53,                                                        // push r11
        0x48, 0x83, 0xEC, 0x28,                                            // sub rsp, 0x28
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,        // mov rcx, <remote_mem>
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,        // mov rax, <load_library>
        0xFF, 0xD0,                                                        // call rax
        0x48, 0x83, 0xC4, 0x28,                                            // add rsp, 0x28
        0x41, 0x5B,                                                        // pop r11
        0x41, 0x5A,                                                        // pop r10
        0x41, 0x59,                                                        // pop r9
        0x41, 0x58,                                                        // pop r8
        0x5A,                                                              // pop rdx
        0x59,                                                              // pop rcx
        0x9D,                                                              // popfq
        0x58,                                                              // pop rax
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,                                // jmp qword ptr [rip+0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00                     // <saved rip>
    };
    static_assert(sizeof(shellcode) == 68, "shellcode layout changed");
    // patch offsets: rcx imm64 @18, rax imm64 @28, saved rip @60
    static_assert(18 == 16 + 2 && 28 == 26 + 2 && 60 == 54 + 6, "shellcode offsets changed");

    *reinterpret_cast<PVOID*>(&shellcode[18]) = remote_mem;
    *reinterpret_cast<PVOID*>(&shellcode[28]) = (PVOID)p_load_library;
    *reinterpret_cast<DWORD64*>(&shellcode[60]) = ctx.Rip;

    LPVOID shellcode_mem = VirtualAllocEx(process, nullptr, sizeof(shellcode),
                                          MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(process, shellcode_mem, shellcode, sizeof(shellcode), nullptr);

    ctx.Rip = (DWORD64)shellcode_mem;
    SetThreadContext(thread, &ctx);
    ResumeThread(thread);

    CloseHandle(thread);
    Sleep(2000);

    VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
    VirtualFreeEx(process, shellcode_mem, 0, MEM_RELEASE);
    CloseHandle(process);

    return { true, L"Successfully hijacked thread." };
#endif // _M_X64
}

injection_result perform_injection(DWORD pid, const injection_settings& settings) {
    const std::wstring actual_path = settings.scramble_dll ? scramble_dll(settings.dll_path)
                                                          : settings.dll_path;

    switch (settings.method) {
    case injection_method::load_library:
        return inject_load_library(pid, actual_path);
    case injection_method::manual_map:
        return inject_manual_map(pid, actual_path, settings.stealth_mode);
    case injection_method::nt_create_thread_ex:
        return inject_nt_create_thread_ex(pid, actual_path);
    case injection_method::thread_hijack:
        return inject_thread_hijack(pid, actual_path);
    default:
        return fail(L"Unknown method.");
    }
}

} // namespace gi

#include "framework.h"
#include "generic injector.h"

#include <winternl.h>

typedef NTSTATUS (NTAPI* _NtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

InjectionResult InjectLoadLibrary(DWORD pid, const std::wstring& dllPath) {
    InjectionResult result = {false, L""};
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        result.message = L"Failed to open process.";
        return result;
    }

    size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, nullptr, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMem) {
        result.message = L"Failed to allocate memory in target process.";
        CloseHandle(hProcess);
        return result;
    }

    if (!WriteProcessMemory(hProcess, pRemoteMem, dllPath.c_str(), pathSize, nullptr)) {
        result.message = L"Failed to write DLL path to target process.";
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMem, 0, nullptr);
    if (!hThread) {
        result.message = L"Failed to create remote thread.";
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }

    WaitForSingleObject(hThread, 5000);
    
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    if (exitCode != 0) {
        result.success = true;
        result.message = L"Successfully injected using LoadLibraryW.";
    } else {
        result.message = L"Thread returned zero.";
    }

    return result;
}

InjectionResult InjectNtCreateThreadEx(DWORD pid, const std::wstring& dllPath) {
    InjectionResult result = {false, L""};
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        result.message = L"Failed to open process.";
        return result;
    }

    size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, nullptr, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMem) {
        result.message = L"Failed to allocate memory in target process.";
        CloseHandle(hProcess);
        return result;
    }

    if (!WriteProcessMemory(hProcess, pRemoteMem, dllPath.c_str(), pathSize, nullptr)) {
        result.message = L"Failed to write DLL path to target process.";
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    _NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    
    if (!NtCreateThreadEx) {
        result.message = L"Failed to find NtCreateThreadEx.";
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }

    HANDLE hThread = nullptr;
    NTSTATUS status = NtCreateThreadEx(&hThread, GENERIC_ALL, nullptr, hProcess, (PVOID)pLoadLibrary, pRemoteMem, 0, 0, 0, 0, nullptr);
    
    if (status == 0 && hThread) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
        result.success = true;
        result.message = L"Successfully injected using NtCreateThreadEx.";
    } else {
        result.message = L"NtCreateThreadEx failed.";
    }

    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return result;
}

typedef HMODULE(WINAPI* fnLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* fnGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI* fnDllMain)(HMODULE, DWORD, LPVOID);

struct ManualMapData {
    fnLoadLibraryA pLoadLibraryA;
    fnGetProcAddress pGetProcAddress;
    HMODULE hModule;
    BOOL success;
};

#pragma runtime_checks("", off)
void __stdcall ShellcodeManualMap(ManualMapData* data) {
    if (!data) return;
    
    BYTE* base = (BYTE*)data->hModule;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(base + dosHeader->e_lfanew);
    
    PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(base + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    DWORD delta = (DWORD)((ULONG_PTR)base - ntHeaders->OptionalHeader.ImageBase);
    while (relocation->VirtualAddress) {
        PWORD relocInfo = (PWORD)(relocation + 1);
        for (int i = 0, count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i < count; i++, relocInfo++) {
            if (*relocInfo >> 12 == IMAGE_REL_BASED_DIR64) {
                *(ULONG_PTR*)(base + relocation->VirtualAddress + (*relocInfo & 0xFFF)) += delta;
            } else if (*relocInfo >> 12 == IMAGE_REL_BASED_HIGHLOW) {
                *(DWORD*)(base + relocation->VirtualAddress + (*relocInfo & 0xFFF)) += delta;
            }
        }
        relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)relocation + relocation->SizeOfBlock);
    }
    
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(base + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        while (importDesc->Name) {
            LPCSTR moduleName = (LPCSTR)(base + importDesc->Name);
            HMODULE hModule = data->pLoadLibraryA(moduleName);
            
            PIMAGE_THUNK_DATA thunkRef = (PIMAGE_THUNK_DATA)(base + importDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA funcRef = (PIMAGE_THUNK_DATA)(base + importDesc->FirstThunk);
            if (!thunkRef) thunkRef = funcRef;
            
            while (thunkRef->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(thunkRef->u1.Ordinal)) {
                    LPCSTR ordinal = (LPCSTR)IMAGE_ORDINAL(thunkRef->u1.Ordinal);
                    funcRef->u1.Function = (ULONG_PTR)data->pGetProcAddress(hModule, ordinal);
                } else {
                    PIMAGE_IMPORT_BY_NAME importName = (PIMAGE_IMPORT_BY_NAME)(base + thunkRef->u1.AddressOfData);
                    funcRef->u1.Function = (ULONG_PTR)data->pGetProcAddress(hModule, (LPCSTR)importName->Name);
                }
                thunkRef++;
                funcRef++;
            }
            importDesc++;
        }
    }
    
    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)(base + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
        if (callback) {
            while (*callback) {
                (*callback)((PVOID)base, DLL_PROCESS_ATTACH, nullptr);
                callback++;
            }
        }
    }
    
    if (ntHeaders->OptionalHeader.AddressOfEntryPoint) {
        fnDllMain dllMain = (fnDllMain)(base + ntHeaders->OptionalHeader.AddressOfEntryPoint);
        dllMain((HMODULE)base, DLL_PROCESS_ATTACH, nullptr);
    }
    
    data->success = TRUE;
}
void ShellcodeManualMapEnd() {}
#pragma runtime_checks("", restore)

InjectionResult InjectManualMap(DWORD pid, const std::wstring& dllPath, bool eraseHeaders) {
    InjectionResult result = {false, L""};
    
    HANDLE hFile = CreateFileW(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        result.message = L"Failed to open DLL file.";
        return result;
    }
    
    DWORD fileSize = GetFileSize(hFile, nullptr);
    std::vector<BYTE> fileBuffer(fileSize);
    DWORD bytesRead;
    ReadFile(hFile, fileBuffer.data(), fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer.data();
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        result.message = L"Invalid DOS signature.";
        return result;
    }
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(fileBuffer.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        result.message = L"Invalid NT signature.";
        return result;
    }
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        result.message = L"Failed to open process.";
        return result;
    }
    
    LPVOID pTargetBase = VirtualAllocEx(hProcess, nullptr, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pTargetBase) {
        result.message = L"Failed to allocate memory for image.";
        CloseHandle(hProcess);
        return result;
    }
    
    WriteProcessMemory(hProcess, pTargetBase, fileBuffer.data(), ntHeaders->OptionalHeader.SizeOfHeaders, nullptr);
    
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sectionHeader[i].SizeOfRawData) {
            WriteProcessMemory(hProcess, (BYTE*)pTargetBase + sectionHeader[i].VirtualAddress, fileBuffer.data() + sectionHeader[i].PointerToRawData, sectionHeader[i].SizeOfRawData, nullptr);
        }
    }
    
    ManualMapData data = {0};
    data.pLoadLibraryA = (fnLoadLibraryA)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");
    data.pGetProcAddress = (fnGetProcAddress)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetProcAddress");
    data.hModule = (HMODULE)pTargetBase;
    data.success = FALSE;
    
    LPVOID pData = VirtualAllocEx(hProcess, nullptr, sizeof(ManualMapData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProcess, pData, &data, sizeof(ManualMapData), nullptr);
    
    size_t shellcodeSize = (BYTE*)ShellcodeManualMapEnd - (BYTE*)ShellcodeManualMap;
    LPVOID pShellcode = VirtualAllocEx(hProcess, nullptr, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, pShellcode, ShellcodeManualMap, shellcodeSize, nullptr);
    
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pShellcode, pData, 0, nullptr);
    if (hThread) {
        WaitForSingleObject(hThread, 10000);
        
        ManualMapData dataBack = {0};
        ReadProcessMemory(hProcess, pData, &dataBack, sizeof(ManualMapData), nullptr);
        
        if (dataBack.success) {
            result.success = true;
            result.message = L"Successfully manually mapped DLL.";
            
            if (eraseHeaders) {
                std::vector<BYTE> emptyHeaders(ntHeaders->OptionalHeader.SizeOfHeaders, 0);
                WriteProcessMemory(hProcess, pTargetBase, emptyHeaders.data(), emptyHeaders.size(), nullptr);
            }
        } else {
            result.message = L"Manual mapping failed during execution.";
        }
        
        CloseHandle(hThread);
    } else {
        result.message = L"Failed to create thread for manual mapping.";
    }
    
    VirtualFreeEx(hProcess, pData, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    return result;
}

InjectionResult InjectThreadHijack(DWORD pid, const std::wstring& dllPath) {
    InjectionResult result = {false, L""};
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        result.message = L"Failed to open process.";
        return result;
    }
    
    size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, nullptr, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProcess, pRemoteMem, dllPath.c_str(), pathSize, nullptr);
    
    FARPROC pLoadLibrary = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    DWORD threadId = 0;
    
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                threadId = te32.th32ThreadID;
                break;
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    CloseHandle(hSnapshot);
    
    if (!threadId) {
        result.message = L"Failed to find thread in target process.";
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }
    
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
    if (!hThread) {
        result.message = L"Failed to open target thread.";
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return result;
    }
    
    SuspendThread(hThread);
    
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);
    
    BYTE shellcode[] = {
        0x50,                                           
        0x9C,                                           
        0x51,                                           
        0x52,                                           
        0x41, 0x50,                                      
        0x41, 0x51,                                      
        0x41, 0x52,                                      
        0x41, 0x53,                                      
        0x48, 0x83, 0xEC, 0x28,                            
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0xFF, 0xD0,                                      
        0x48, 0x83, 0xC4, 0x28,                            
        0x41, 0x5B,                                      
        0x41, 0x5A,                                      
        0x41, 0x59,                                      
        0x41, 0x58,                                      
        0x5A,                                           
        0x59,                                           
        0x9D,                                           
        0x58,                                           
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,                  
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00   
    };
    
    *reinterpret_cast<PVOID*>(&shellcode[18]) = pRemoteMem;
    *reinterpret_cast<PVOID*>(&shellcode[28]) = pLoadLibrary;
    *reinterpret_cast<DWORD64*>(&shellcode[60]) = ctx.Rip;
    
    LPVOID pShellcode = VirtualAllocEx(hProcess, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, pShellcode, shellcode, sizeof(shellcode), nullptr);
    
    ctx.Rip = (DWORD64)pShellcode;
    SetThreadContext(hThread, &ctx);
    
    ResumeThread(hThread);
    CloseHandle(hThread);
    
    Sleep(2000);
    
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    result.success = true;
    result.message = L"Successfully hijacked thread.";
    return result;
}

InjectionResult PerformInjection(DWORD pid, const InjectionSettings& settings) {
    std::wstring actualPath = settings.dllPath;
    if (settings.scrambleDll) {
        actualPath = ScrambleDll(settings.dllPath);
    }
    
    switch (settings.method) {
        case InjectionMethod::LoadLibrary:
            return InjectLoadLibrary(pid, actualPath);
        case InjectionMethod::NtCreateThreadEx:
            return InjectNtCreateThreadEx(pid, actualPath);
        case InjectionMethod::ManualMap:
            return InjectManualMap(pid, actualPath, settings.stealthMode);
        case InjectionMethod::ThreadHijack:
            return InjectThreadHijack(pid, actualPath);
        default:
            return {false, L"Unknown method."};
    }
}

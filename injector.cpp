#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <Psapi.h>

HHOOK hKeyboardHook;

void RemoveTrapPages(HANDLE hProcess) {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID lpAddress = NULL;

    while (VirtualQueryEx(hProcess, lpAddress, &mbi, sizeof(mbi))) {
        // Check if the memory region is a trap page (MEM_FREE).
        if (mbi.State == MEM_FREE) {
            std::cout << "Removing trap page at address: " << mbi.BaseAddress << std::endl;

            // Remove the trap page by freeing it.
            VirtualFreeEx(hProcess, mbi.BaseAddress, 0, MEM_RELEASE);
        }

        // Move to the next memory region.
        lpAddress = reinterpret_cast<LPVOID>(reinterpret_cast<char*>(mbi.BaseAddress) + mbi.RegionSize);
    }
}

// Function to enable the SE_DEBUG_NAME privilege for a given process and return the target thread ID
std::pair<DWORD, HANDLE> EnableAllPrivilegesForProcess(const wchar_t* targetModuleName) {
    DWORD targetThreadId = 0;
    HANDLE hToken = NULL;

    // Find the RobloxPlayerBeta.exe process by name
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &processEntry)) {
            do {
                if (_wcsicmp(processEntry.szExeFile, targetModuleName) == 0) {
                    DWORD processId = processEntry.th32ProcessID;

                    // Attempt to open the process handle
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
                    if (hProcess != NULL) {
                        // Attempt to open the process token
                        if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                            // Enable all privileges for the process token
                            TOKEN_PRIVILEGES tokenPrivileges;
                            tokenPrivileges.PrivilegeCount = 4;  // Set count to 0 to enable all privileges

                            TCHAR processName[MAX_PATH];
                            if (GetProcessImageFileName(hProcess, processName, MAX_PATH) > 0) {
                                std::wcout << L"The process name for the elevated thread is: " << processName << std::endl;
                            }

                            if (AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
                                // Close the process handle
                                RemoveTrapPages(hProcess);
                                CloseHandle(hProcess);

                                // Take a snapshot of the threads in the specified process
                                HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                                if (hThreadSnapshot != INVALID_HANDLE_VALUE) {
                                    THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
                                    if (Thread32First(hThreadSnapshot, &threadEntry)) {
                                        do {
                                            if (threadEntry.th32OwnerProcessID == processId) {
                                                // Optionally, you can add additional checks here to determine the target thread
                                                targetThreadId = threadEntry.th32ThreadID;
                                                break;
                                            }
                                        } while (Thread32Next(hThreadSnapshot, &threadEntry));
                                    }
                                    CloseHandle(hThreadSnapshot);
                                }
                            }
                            else {
                                std::cerr << "Failed to enable all privileges for the process token. Error: " << GetLastError() << std::endl;
                                CloseHandle(hToken);  // Close the token handle in case of failure
                                CloseHandle(hProcess);
                            }
                        }
                        else {
                            std::cerr << "Failed to open process token. Error: " << GetLastError() << std::endl;
                            CloseHandle(hProcess);  // Close the process handle in case of failure
                        }
                    }
                    else {
                        std::cerr << "Failed to open target process. Error: " << GetLastError() << std::endl;
                    }

                    // Break the loop once the target process is found
                    break;
                }
            } while (Process32Next(hSnapshot, &processEntry));
        }
        else {
            std::cerr << "Process32First failed. Error: " << GetLastError() << std::endl;
        }
        CloseHandle(hSnapshot);
    }
    else {
        std::cerr << "CreateToolhelp32Snapshot failed. Error: " << GetLastError() << std::endl;
    }

    return std::make_pair(targetThreadId, hToken);
}

// Function to retrieve and print the permissions of a thread
void PrintPrivileges(HANDLE hToken) {
    DWORD dwLengthNeeded;
    if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwLengthNeeded) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Failed to retrieve token privileges. Error: " << GetLastError() << std::endl;
        return;
    }

    PTOKEN_PRIVILEGES tokenPrivileges = reinterpret_cast<PTOKEN_PRIVILEGES>(new BYTE[dwLengthNeeded]);

    if (!GetTokenInformation(hToken, TokenPrivileges, tokenPrivileges, dwLengthNeeded, &dwLengthNeeded)) {
        std::cerr << "Failed to retrieve token privileges. Error: " << GetLastError() << std::endl;
        delete[] tokenPrivileges;
        return;
    }

    std::cout << "Privileges after elevation:" << std::endl;
    for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; i++) {
        LUID_AND_ATTRIBUTES privilege = tokenPrivileges->Privileges[i];
        DWORD privilegeNameLength = 0;
        LookupPrivilegeName(NULL, &privilege.Luid, NULL, &privilegeNameLength);

        if (privilegeNameLength > 0) {
            std::vector<wchar_t> privilegeName(privilegeNameLength);
            if (LookupPrivilegeName(NULL, &privilege.Luid, privilegeName.data(), &privilegeNameLength)) {
                std::wcout << L"  " << privilegeName.data();
                if (privilege.Attributes & SE_PRIVILEGE_ENABLED) {
                    std::wcout << L" (Enabled)";
                }
                std::wcout << std::endl;

                // Check for specific privileges (e.g., read and write)
                if (wcscmp(privilegeName.data(), L"SeBackupPrivilege") == 0) {
                    std::wcout << L"    (This privilege allows backup access)" << std::endl;
                }
                if (wcscmp(privilegeName.data(), L"SeRestorePrivilege") == 0) {
                    std::wcout << L"    (This privilege allows restore access)" << std::endl;
                }
                // Add more checks for other privileges as needed
            }
        }
    }

    delete[] tokenPrivileges;
}

DWORD GetProcessIdByName(const wchar_t* processName) {
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    DWORD processId = 0; // Initialize with an invalid value

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                processId = pe32.th32ProcessID; // Store the process ID
                break; // Exit the loop when found
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return processId;
}

unsigned char payload[] = "\x33\xc9\x64\x8b\x49\x30\x8b\x49\x0c\x8b"
"\x49\x1c\x8b\x59\x08\x8b\x41\x20\x8b\x09"
"\x80\x78\x0c\x33\x75\xf2\x8b\xeb\x03\x6d"
"\x3c\x8b\x6d\x78\x03\xeb\x8b\x45\x20\x03"
"\xc3\x33\xd2\x8b\x34\x90\x03\xf3\x42\x81"
"\x3e\x47\x65\x74\x50\x75\xf2\x81\x7e\x04"
"\x72\x6f\x63\x41\x75\xe9\x8b\x75\x24\x03"
"\xf3\x66\x8b\x14\x56\x8b\x75\x1c\x03\xf3"
"\x8b\x74\x96\xfc\x03\xf3\x33\xff\x57\x68"
"\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68"
"\x4c\x6f\x61\x64\x54\x53\xff\xd6\x33\xc9"
"\x57\x66\xb9\x33\x32\x51\x68\x75\x73\x65"
"\x72\x54\xff\xd0\x57\x68\x6f\x78\x41\x01"
"\xfe\x4c\x24\x03\x68\x61\x67\x65\x42\x68"
"\x4d\x65\x73\x73\x54\x50\xff\xd6\x57\x68"
"\x72\x6c\x64\x21\x68\x6f\x20\x57\x6f\x68"
"\x48\x65\x6c\x6c\x8b\xcc\x57\x57\x51\x57"
"\xff\xd0\x57\x68\x65\x73\x73\x01\xfe\x4c"
"\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78"
"\x69\x74\x54\x53\xff\xd6\x57\xff\xd0";

int main() {
    const wchar_t* targetModuleName = L"RobloxPlayerBeta.exe";

    std::pair<DWORD, HANDLE> result = EnableAllPrivilegesForProcess(targetModuleName);
    DWORD targetThreadId = result.first;
    HANDLE hToken = result.second;

    if (targetThreadId != 0) {
        HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, targetThreadId);
        HANDLE robloxHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetProcessIdByName(L"RobloxPlayerBeta.exe"));

        if (robloxHandle != NULL && threadHandle != NULL) {
            PVOID rBuffer = VirtualAllocEx(robloxHandle, NULL, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (rBuffer != NULL) {
                SIZE_T bytesWritten;
                if (WriteProcessMemory(robloxHandle, rBuffer, payload, sizeof(payload), &bytesWritten) != 0) {
                    if (bytesWritten == sizeof(payload)) {
                        std::cout << "Wrote payload to memory successfully" << std::endl;

                        CONTEXT ct;
                        SuspendThread(threadHandle);
                        GetThreadContext(threadHandle, &ct);
                        ct.Rip = reinterpret_cast<DWORD_PTR>(rBuffer);
                        SetThreadContext(threadHandle, &ct);
                        ResumeThread(threadHandle);
                    }
                    else {
                        std::cerr << "Failed to write the full payload to memory" << std::endl;
                    }
                }
                else {
                    std::cerr << "Failed to write to memory. Error: " << GetLastError() << std::endl;
                }

                VirtualFreeEx(robloxHandle, rBuffer, 0, MEM_RELEASE);
            }
            else {
                std::cerr << "Failed to allocate memory in the target process. Error: " << GetLastError() << std::endl;
            }
        }
        else {
            std::cerr << "Failed to open process or thread handles. Error: " << GetLastError() << std::endl;
        }

        if (threadHandle != NULL) {
            CloseHandle(threadHandle);
        }
        if (robloxHandle != NULL) {
            CloseHandle(robloxHandle);
        }
    }
    else {
        std::cerr << "Failed to obtain target thread ID or enable privileges." << std::endl;
    }

    if (hToken != NULL) {
        CloseHandle(hToken);
    }

    return 0;
}

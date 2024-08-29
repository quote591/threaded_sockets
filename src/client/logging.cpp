#include "logging.hpp"

#include <ctime>

// Static
Log* Log::pInstance = nullptr;
std::mutex Log::instanceMutex;


Log::Log()
{
    std::time_t now = std::time(nullptr);
    // Log_dd_mm_yy-mm_ss_mss.txt
    char fileNameBuffer[64];

    // day [00-31] month [00-12] year[00-99] - hour [00-24] minute [00-60] second [00-60]
    if (!(std::strftime(fileNameBuffer, sizeof(fileNameBuffer), "../../../logs/Log_%d_%m_%y-%H_%M_%S.txt", std::localtime(&now))))
        throw("strftime error.");

    f.open(fileNameBuffer, std::ios::out);
}


Log::~Log()
{
    f.close();
}


Log *Log::s_GetInstance(void)
{
    std::lock_guard<std::mutex> lock(instanceMutex);
    if (pInstance == nullptr)
    {
        pInstance = new Log();
    }
    return pInstance;
}

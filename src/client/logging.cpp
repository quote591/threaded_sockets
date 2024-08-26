#include "logging.hpp"

#include <ctime>
#include <sstream>
#include <thread>

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

void Log::m_LogWrite(std::string moduleFunction, std::string message)
{
    // Idea, print the thread ID into this so we know which thread is doing what?
    // Could maybe use a map when the thread starts it enters its ID with the name i.e. DrawThread
    // Then when a call is made we can sub the ID with the affiliated name?
    std::lock_guard<std::mutex> lock(writeMutex);

    auto elapsed = std::chrono::high_resolution_clock::now() - this->startTimePoint;
    
    std::string mins_elapsed = std::to_string(std::chrono::duration_cast<std::chrono::minutes>(elapsed).count()%60);
    mins_elapsed.insert(0, 2-mins_elapsed.size(), '0');

    std::string sec_elapsed = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count()%60);
    sec_elapsed.insert(0, 2-sec_elapsed.size(), '0');

    std::string mss_elapsed = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()%1000);
    mss_elapsed.insert(0, 3-mss_elapsed.size(), '0');

    std::stringstream ss;
    
    // [00:00:001][modulesFunction] : message (threadID)
    ss << "[" << mins_elapsed << ":" << sec_elapsed << ":" << mss_elapsed << "]"
        << "[" << moduleFunction << "\t] : " << message << " (th_id " << std::this_thread::get_id() << ")" << "\n";
    
    // std::cout << ss.str() << " " << ss.str().size() << std::endl;
    f.write(ss.str().c_str(), ss.str().size());
    f.flush();
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

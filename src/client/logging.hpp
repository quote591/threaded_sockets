#include <fstream>
#include <chrono> // High precision clock
#include <mutex>

// Thread safe singleton logging class
class Log
{
private:
    std::ofstream f;
    std::chrono::high_resolution_clock::time_point startTimePoint = std::chrono::high_resolution_clock::now();

    Log();
    ~Log();

    static Log* pInstance;

    std::mutex writeMutex;
    static std::mutex instanceMutex;
public:

    // @brief Logging function that writes message into file within logs/
    // @param modelFunction - string of the method or system making the log
    // @param message - log message
    void m_LogWrite(std::string moduleFunction, std::string message);

    // Singleton 
    void operator=(const Log&) = delete;
    
    // @brief Thread safe get the instance of the class
    // @return pointer to the instance of the class. If not created it will do
    static Log* s_GetInstance(void);
};

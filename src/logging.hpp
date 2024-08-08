#include <fstream>
#include <chrono> // High precision clock

class Log
{
private:
    std::ofstream f;
    std::chrono::high_resolution_clock::time_point startTimePoint = std::chrono::high_resolution_clock::now();

public:
    Log();
    ~Log();

    // @brief Logging function that writes message into file within logs/
    // @args modelFunction - string of the method or system making the log
    // @args message - log message
    void m_LogWrite(std::string moduleFunction, std::string message);
};

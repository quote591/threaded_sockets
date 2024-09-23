#include <fstream>
#include <chrono> // High precision clock
#include <mutex>
#include <sstream>
#include <thread>

// Thread safe singleton logging class
class Log
{
private:
    std::ofstream f;
    std::chrono::high_resolution_clock::time_point startTimePoint = std::chrono::high_resolution_clock::now();

    Log();
    ~Log();

    static std::unique_ptr<Log> pInstance;

    // Declare make unique as a friend so that it can access private constructor and destructor
    friend std::unique_ptr<Log> std::make_unique<Log>();
    friend struct std::default_delete<Log>;

    std::mutex writeMutex;
    static std::mutex instanceMutex;
public:
    // Singleton 
    void operator=(const Log&) = delete;


    /// @brief Thread safe get the instance of the class
    /// @return pointer to the instance of the class. If not created it will do
    static Log* s_GetInstance(void);


    /// @brief Logging function that writes message into file within logs/
    /// @param modelFunction - string of the method or system making the log
    /// @param message - log message
    template<typename... Args>
    void m_LogWrite(const std::string& moduleFunction, Args&&... message);

};


// Final case for the multiple arguments
template<typename T>
void formatMessage(std::ostringstream& oss, T&& t) {
    oss << std::forward<T>(t);
}

// Next argument and the argument list
template<typename T, typename... Args>
void formatMessage(std::ostringstream& oss, T&& t, Args&&... args) {
    oss << std::forward<T>(t);
    formatMessage(oss, std::forward<Args>(args)...);
}

template<typename... Args>
void Log::m_LogWrite(const std::string& moduleFunction, Args&&... message)
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
    std::ostringstream oss;

    formatMessage(oss, std::forward<Args>(message)...);
    
    // [00:00:001][modulesFunction] : message (threadID)
    ss << "[" << mins_elapsed << ":" << sec_elapsed << ":" << mss_elapsed << "]"
        << "[" << moduleFunction << "\t] : " << oss.str() << "(th_id " << std::this_thread::get_id() << ")" << "\n";
    
    f.write(ss.str().c_str(), ss.str().size());
    f.flush();
}

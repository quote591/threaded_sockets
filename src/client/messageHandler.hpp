#include <vector>
#include <string>
#include <mutex>
#include <atomic>
#include <thread>
#include <queue>
#include <memory>

// Forward declaration
class Packet;

class MessageHandler
{
private:
    std::vector<std::string> m_displayBuffer;
    std::vector<char> m_inputBuffer;
    std::queue<std::unique_ptr<Packet>> m_sendMessageQueue;
    
    std::mutex m_inputBufferMutex; // For input buffer resource
    std::mutex m_displayBufferMutex; // For display buffer resource
    std::mutex m_sendMessageQueueMutex; // For the send message queue
    
    // Atomic to indicate a return
    std::atomic<int> m_threadReturn{0};
    std::thread m_threadHandle;

    static std::string m_userAlias;
    static std::mutex m_userAliasMutex;

public:
    static std::atomic<bool> m_aliasSet;

    // Idea - thread spools up in constructor and joins in destructor for input handling
    MessageHandler();
    ~MessageHandler();

    static void s_SetUserAlias(const std::string& alias);
    static std::string s_GetUserAlias(void);

    /// @brief Append a character onto the input buffer (thread safe)
    /// @param char c - character
    void m_PushInputBuffer(char c);


    /// @brief Will delete the last character in the input buffer
    void m_DelCharInputBuffer(void);


    /// @brief Will empty the input buffer in a thread safe way
    void m_ClearInputBuffer(void);


    /// @brief Get the input buffer (thread safe)
    /// @return A copy of the input buffer
    std::vector<char> m_GetInputBuffer(void);


    /// @brief Get input buffer string (thread safe)
    /// @returns Copy string
    std::string m_GetInputBufferStr(void);


    /// @brief return the size of the input buffer
    int m_GetInputBufferSize(void);


    /// @brief adds message to queue (thread safe)
    /// @param msgType Type of message
    /// @param msg - message to send via network socket
    void m_PushMessageToSendQueue(unsigned char msgType, std::string msg);


    /// @brief return the number of messages in the queue
    /// @return number of elements in the queue.
    int m_GetSizeofSendQueue(void);


    /// @brief get the oldest message on the queue
    /// @return return unique ptr of 
    std::unique_ptr<Packet> m_GetMessageFromSendQueue(void);


    /// @brief Get the sent messages (thread safe)
    /// @param lines - Get n amount of messages from the entire vector
    /// @return copy of the data
    std::vector<std::string> m_GetDisplayMessages(size_t lines);


    /// @brief Add message to display buffer (thread safe)
    /// @param str - message by reference
    void m_PushMessageToDisplay(std::string& str);


    /// @brief Thread safe way to empty the display buffer
    void m_ClearDisplayBuffer(void);


    /// @brief Input handler. Deals with all keystrokes and what to do
    void m_HandleInput(void);


    /// @brief method to return the threads
    void m_ReturnThreads(void);

};

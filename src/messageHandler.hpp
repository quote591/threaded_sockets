#include <vector>
#include <string>
#include <mutex>
#include <atomic>
#include <thread>
#include <queue>

// Output overload for std::vector<char> (Input buffer)
// std::ostream& operator<<(std::ostream& os, const std::vector<char>& vec)
// {
//     for (char c : vec)
//         os << c;
//     return os;
// }

class MessageHandler
{
private:
    std::vector<std::string> m_displayBuffer;
    std::vector<char> m_inputBuffer;
    std::queue<std::string> m_sendMessageQueue;
    
    std::mutex m_inputBufferMutex; // For input buffer resource
    std::mutex m_displayBufferMutex; // For display buffer resource
    std::mutex m_sendMessageQueueMutex; // For the send message queue
    

    // Atomic to indicate a return
    std::atomic<int> m_threadReturn{0};
    std::thread m_threadHandle;

public:

    // Idea - thread spools up in constructor and joins in destructor for input handling
    MessageHandler();
    ~MessageHandler();

    std::string ToLowerCase(std::string stringIn)
    {
        std::string result = "";
        for (auto ch : stringIn)
            result += std::tolower(ch);
        return result;
    }

    // @brief Append a character onto the input buffer (thread safe)
    // @param char c - character
    void m_PushInputBuffer(char c);

    // @brief Will delete the last character in the input buffer
    void m_DelCharInputBuffer(void);

    // @brief Get the input buffer (thread safe)
    // @return A copy of the input buffer
    std::vector<char> m_GetInputBuffer(void);

    // @brief Get input buffer string (thread safe)
    // @returns Copy string
    std::string m_GetInputBufferStr(void);

    // @brief return the size of the input buffer
    int m_GetInputBufferSize(void);

    // @brief adds message to queue (thread safe)
    // @param msg - message to send via network socket
    void m_PushMessageToSendQueue(std::string msg);

    // @brief return the number of messages in the queue
    // @return number of elements in the queue.
    int m_GetSizeofSendQueue(void);

    // @brief get the oldest message on the queue
    // @return copy of the message
    std::string m_GetMessageFromSendQueue(void);

    // @brief Get the sent messages (thread safe)
    // @param lines - Get n amount of messages from the entire vector
    // @return copy of the data
    std::vector<std::string> m_GetDisplayMessages(size_t lines);

    // @brief Add message to display buffer (thread safe)
    // @param str - message by reference
    void m_PushMessageToDisplay(std::string& str);

    // @brief Thread safe way to empty the display buffer
    void m_ClearDisplayBuffer(void);

    // @brief Input handler. Deals with all keystrokes and what to do
    void m_HandleInput(void);

    // @brief method to return the threads
    void m_ReturnThreads(void);

};

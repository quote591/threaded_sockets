#include <vector>
#include <string>
#include <mutex>

// Output overload for std::vector<char> (Input buffer)
std::ostream& operator<<(std::ostream& os, const std::vector<char>& vec)
{
    for (char c : vec)
        os << c;
    return os;
}

class MessageHandler
{
private:
    std::vector<std::string> m_displayBuffer;
    std::vector<char> m_inputBuffer;
    
    std::mutex m_inputBufferMutex;
    std::mutex m_displayBufferMutex;
public:
    // Idea - thread spools up in constructor and joins in destructor for input handling

    // @brief Append a character onto the input buffer (thread safe)
    // @args char c - character
    void m_pushInputBuffer(char c);

    // @brief Will delete the last character in the input buffer
    void m_delCharInputBuffer(void);

    // @brief Get the input buffer (thread safe)
    // @return A copy of the input buffer
    std::vector<char> m_getInputBuffer(void);

    // @brief Get input buffer string (thread safe)
    // @returns Copy string
    std::string m_getInputBufferStr(void);


    // @brief Add message to display buffer (thread safe)
    // @args str - message by reference
    void m_pushMessageToDisplay(std::string& str);

    // @brief Thread safe way to empty the display buffer
    void m_clearDisplayBuffer(void);

    // @brief Input handler. Deals with all keystrokes and what to do
    void m_handleInput(void);


};
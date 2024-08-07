#include "messageHandler.hpp"
#include "display.hpp"
#include <sstream>
#include <thread>

#include <conio.h> // _kbhit(), _getch()

void MessageHandler::m_pushInputBuffer(char c)
{
    std::lock_guard<std::mutex> lock_input(m_inputBufferMutex);
    m_inputBuffer.push_back(c);
}

void MessageHandler::m_delCharInputBuffer(void)
{
    std::lock_guard<std::mutex> lock_input(m_inputBufferMutex);
    m_inputBuffer.pop_back();
}

std::vector<char> MessageHandler::m_getInputBuffer(void)
{
    std::lock_guard<std::mutex> lock_input(m_inputBufferMutex);
    return m_inputBuffer;
}

std::string MessageHandler::m_getInputBufferStr(void)
{
    std::lock_guard<std::mutex> lock_input(m_inputBufferMutex);
    // Construct string and return
    std::stringstream ss;
    for (char c : m_inputBuffer)
        ss << c;    
    return ss.str();
}

void MessageHandler::m_pushMessageToDisplay(std::string &str)
{
    std::lock_guard<std::mutex> lock_display(m_displayBufferMutex);
    m_displayBuffer.push_back(str);
}

void MessageHandler::m_clearDisplayBuffer(void)
{
    std::lock_guard<std::mutex> lock_display(m_displayBufferMutex);
    m_displayBuffer.clear();
}

void MessageHandler::m_handleInput(void)
{
    char c;
    while (true) {
        if (_kbhit()) {  // Check if a key is pressed
            c = _getch();  // Read the key press without buffering (no await enter key)
            if (c == '\r' || c == '\n') { 
                // std::cout << "Enter key pressed." << std::endl;
                int column, row;
                // GetConsoleMaxCoord(column, row);
                // addMessageToDisplay(inputBuffer, column, row);
                // Here we can do checks like is input "Exit", then we return.
                // break;
            }
            else if(c == 27) // ASCII ESC
            {
                break;
            }
            // If char is printable then we can add it to our buffer
            if (std::isprint(c))
            {
                // pushInputBuffer(c);
                // std::cout << c;
            }
            else if (c == 8 && m_inputBuffer.size() != 0) // backspace
            {
                // deleteLastCharacter();
                // std::cout << "\b \b";
            }
        }
        // Small delay to avoid the heavy load
        std::this_thread::sleep_for(std::chrono::milliseconds(30));

        // Check flag for exit

    }
}

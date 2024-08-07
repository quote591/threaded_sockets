#include "messageHandler.hpp"

#include "display.hpp"

#include <sstream>
#include <thread>
#include <iostream> // TODO REMOVE
#include <conio.h> // _kbhit(), _getch()

MessageHandler::MessageHandler()
{
    m_threadHandle = std::thread(m_HandleInput, this);
}

MessageHandler::~MessageHandler()
{
    m_threadHandle.join();
}

void MessageHandler::m_PushInputBuffer(char c)
{
    std::lock_guard<std::mutex> lock_input(m_inputBufferMutex);
    m_inputBuffer.push_back(c);
}

void MessageHandler::m_DelCharInputBuffer(void)
{
    std::lock_guard<std::mutex> lock_input(m_inputBufferMutex);
    m_inputBuffer.pop_back();
}

std::vector<char> MessageHandler::m_GetInputBuffer(void)
{
    std::lock_guard<std::mutex> lock_input(m_inputBufferMutex);
    return m_inputBuffer;
}

std::string MessageHandler::m_GetInputBufferStr(void)
{
    std::lock_guard<std::mutex> lock_input(m_inputBufferMutex);
    // Construct string and return
    std::stringstream ss;
    for (char c : m_inputBuffer)
        ss << c;    
    return ss.str();
}

void MessageHandler::m_PushMessageToDisplay(std::string &str)
{
    std::lock_guard<std::mutex> lock_display(m_displayBufferMutex);
    m_displayBuffer.push_back(str);
}

void MessageHandler::m_ClearDisplayBuffer(void)
{
    std::lock_guard<std::mutex> lock_display(m_displayBufferMutex);
    m_displayBuffer.clear();
}

void MessageHandler::m_HandleInput(void)
{
    char c;
    while (true) {
        if (_kbhit()) {  // Check if a key is pressed
            c = _getch();  // Read the key press without buffering (no await enter key)
            if (c == '\r' || c == '\n') { 
                // std::cout << "Enter key pressed." << std::endl;
                // short column, row;
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
                std::cout << c;
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
        if (m_threadReturn)
        {
            delete(this);
            return;
        }
    }
}

void MessageHandler::m_ReturnThreads(void)
{
    m_threadReturn^=1;
}

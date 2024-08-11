#include "messageHandler.hpp"

#include "display.hpp"
#include "logging.hpp"

#include <sstream>
#include <thread>
#include <conio.h> // _kbhit(), _getch()


MessageHandler::MessageHandler()
{
    Log::s_GetInstance()->m_LogWrite("MessageHandler::MessageHandler()", "Thread started");
    // m_threadHandle = std::thread(m_HandleInput, this);
}


MessageHandler::~MessageHandler()
{
    Log::s_GetInstance()->m_LogWrite("MessageHandler::~MessageHandler()", "Thread joined");
    // m_threadHandle.join();
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


void MessageHandler::m_ClearInputBuffer(void)
{
    std::lock_guard<std::mutex> lock_input(m_inputBufferMutex);
    m_inputBuffer.clear();
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


int MessageHandler::m_GetInputBufferSize(void)
{
    return static_cast<int>(m_inputBuffer.size());
}


void MessageHandler::m_PushMessageToSendQueue(std::string msg)
{
    std::lock_guard<std::mutex> lock_display(m_sendMessageQueueMutex);
    m_sendMessageQueue.push(msg);
}


int MessageHandler::m_GetSizeofSendQueue(void)
{
    std::lock_guard<std::mutex> lock_display(m_sendMessageQueueMutex);
    return m_sendMessageQueue.size();
}


std::string MessageHandler::m_GetMessageFromSendQueue(void)
{
    std::lock_guard<std::mutex> lock_display(m_sendMessageQueueMutex);
    std::string msg;
    msg = m_sendMessageQueue.front();
    m_sendMessageQueue.pop();
    return msg;
}


std::vector<std::string> MessageHandler::m_GetDisplayMessages(size_t lines)
{
    std::lock_guard<std::mutex> lock_display(m_displayBufferMutex);

    // If the number of entries are less than the requested amount. Just return what we have
    size_t numberOfMessages = lines;
    if (m_displayBuffer.size() < lines)
        numberOfMessages = m_displayBuffer.size();

    std::vector<std::string> returnMessages;

    for (size_t i = 0; i < numberOfMessages; i++)
    {
        returnMessages.push_back(m_displayBuffer[m_displayBuffer.size()-i-1]);
    }
    return returnMessages;
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

// This method always assumes our cursor is in the input box at the correct position
// as it should be handled by the display class
void MessageHandler::m_HandleInput(void)
{
    char c;
    while (true) {
        if (_kbhit()) {  // Check if a key is pressed
            c = _getch();  // Read the key press without buffering (no await enter key)
            if (c == '\r' || c == '\n') { 
                Log::s_GetInstance()->m_LogWrite("MessageHandler::m_HandleInput()", "Enter key pressed");
                // Handle a Network socket send.
                // The server will return the message to you which will then put it in the message history
                // The message history is the definative proof that a message has been sent
                
                if (ToLowerCase(this->m_GetInputBufferStr()) == "exit")
                {
                    Log::s_GetInstance()->m_LogWrite("MessageHandler::m_HandleInput()", "Exit command recieved.");
                    return;
                }
                // Get the input buffer and add it to the send queue
                this->m_PushMessageToSendQueue(this->m_GetInputBufferStr());
                // Empty the input buffer
                this->m_ClearInputBuffer();
                Display::s_ClearInputField();
            }
            else if(c == 27) // ASCII ESC
            {
                Log::s_GetInstance()->m_LogWrite("MessageHandler::m_HandleInput()", "ESC key pressed");
                return; // Return thread
            }
            // If char is printable then we can add it to our buffer
            if (std::isprint(c))
            {
                std::stringstream ss;
                this->m_PushInputBuffer(c);
                Display::s_WriteToInputDisplay(c);

                ss << "Pushing character to input buffer: " << c << " Total length(" << this->m_GetInputBufferStr().size() << ")";
                Log::s_GetInstance()->m_LogWrite("MessageHandler::m_HandleInput()", ss.str());

            }
            else if (c == 8 && m_inputBuffer.size() != 0) // backspace
            {
                Log::s_GetInstance()->m_LogWrite("MessageHandler::m_HandleInput()", "Backspace pressed");
                this->m_DelCharInputBuffer();
                Display::s_WriteToInputDisplay("\b \b");
            }
        }
        // Small delay to avoid the heavy load
        std::this_thread::sleep_for(std::chrono::milliseconds(30));

        // Check flag for exit
        if (m_threadReturn)
        {
            Log::s_GetInstance()->m_LogWrite("MessageHandler::m_HandleInput()", "Thread returned");
            return;
        }
    }
}


void MessageHandler::m_ReturnThreads(void)
{
    Log::s_GetInstance()->m_LogWrite("MessageHandler::m_ReturnThreads()", "Updating m_threadReturn flag");
    m_threadReturn^=1;
}

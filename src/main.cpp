#include "display.hpp"
#include "messageHandler.hpp"
#include "logging.hpp"

#include <thread>
#include <memory>

#include <iostream>

std::unique_ptr<MessageHandler> mh;

int main()
{
    Log* lg = new Log();

    
    lg->m_LogWrite("NetworkRecv()", "63 bytes recieved from 127.0.0.1");
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    lg->m_LogWrite("NetworkRecv()", "12 bytes recieved from 127.0.0.1");
    std::this_thread::sleep_for(std::chrono::seconds(60));
    lg->m_LogWrite("NetworkRecv()", "54 bytes recieved from 127.0.0.1");



    delete(lg);
    return 0;


    // Thread to handle the user input at all times
    mh = std::make_unique<MessageHandler>();
    
    // Another thread needed for Drawing to the screen

    // Another thread needed for handing of network traffic.

    Display::s_SetTerminalModeRaw();

    while(true)
    {
        Display::s_ClearTerminal();
        Display::s_Draw(Display::s_writeToScreenMutex);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    mh->m_ReturnThreads();

    // std::cout << "Hello, world!" << std::endl;
    return 0;
}

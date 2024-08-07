#include <iostream>
#include "display.hpp"
#include "messageHandler.hpp"
#include <thread>
#include <memory>

std::unique_ptr<MessageHandler> mh;

int main()
{
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

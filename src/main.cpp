#include "display.hpp"
#include "messageHandler.hpp"
#include "logging.hpp"

#include <thread>
#include <memory>

#include <iostream>

MessageHandler* mh;
std::atomic<int> drawThreadReturn{0};


void DrawThreadMethod(void)
{
    Display::s_ClearTerminal();
    Display::s_Draw(mh);
    short oldColumn, oldRow;
    Display::s_GetConsoleMaxCoords(oldColumn, oldRow);
    while (true)
    {
        short column, row;
        Display::s_GetConsoleMaxCoords(column, row);

        if (oldColumn != column || oldRow != row /*|| updateDraw*/)
        {
            Display::s_ClearTerminal();
            Display::s_Draw(mh);
            oldColumn = column; oldRow = row;
            // updateDraw^=1;
        }
            
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        if (drawThreadReturn) {return;}
    }
}



int main()
{

    // Thread to handle the user input at all times
    mh = new MessageHandler();

    std::string messages[] = {"Message 1", "Test message", "Hello how are we?", "This is cool i guesss."};

    for (std::string msg : messages)
        mh->m_PushMessageToDisplay(msg);


    Display::s_SetTerminalModeRaw();

    // Another thread needed for Drawing to the screen
    std::thread drawThread(DrawThreadMethod);







    // Another thread needed for handing of network traffic.

    

    std::this_thread::sleep_for(std::chrono::milliseconds(20000));
    


    mh->m_ReturnThreads();
    drawThreadReturn^=1;

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    

    // Terminate with no exception code3. Most likley issue:
    // When threads are .joinable() and program exits this can happen.
    // Need a way to rejoin the thread before we exit. Descructor is not called in time (where the thread is joined)
    // mh.get_deleter(); 
    drawThread.join();

    delete(mh);
    // std::cout << "Hello, world!" << std::endl;
    return 0;
}

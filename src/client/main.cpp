#include "display.hpp"
#include "messageHandler.hpp"
#include "logging.hpp"
#include "network/networkHandler.hpp"

#include <thread>
#include <memory>

MessageHandler* p_messageHandler;
NetworkHandler* p_networkHandler;

std::atomic<bool> returnThreads{false};

const std::string hostname = "192.168.1.114";
const std::string port = "27011";

// UpdateRate
#define THREADUPDATERATE 60 // hz
constexpr int msThreadDelay = 1000/THREADUPDATERATE;

// Should run a certain amount of updates a second (60hz)
// 1000/60 ms wait per cycle. 
void HandleNetwork(void)
{
    p_networkHandler = new NetworkHandler();

    p_networkHandler->m_Create(hostname, port);
    
    // Keep trying to connect until we do
    while (true)
    {
        if(p_networkHandler->m_Connect())
        {
            Display::s_DrawInfoDisplayMux(p_messageHandler);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(msThreadDelay));

        // Return threads
        if (returnThreads)
        {
            p_networkHandler->m_Close();
            return;
        }
    }
    // Recv and send any data that is available
    while (true)
    {

        // Recv message and add to the message display
        std::string recvMsg;
        if (p_networkHandler->m_ReceiveMessage(recvMsg, p_messageHandler))
        {
            p_messageHandler->m_PushMessageToDisplay(recvMsg);
            Display::s_DrawMessageDisplay(p_messageHandler);
            Display::s_DrawInfoDisplayMux(p_messageHandler);
        }
        // We check if there is a disconnect
        else
        {
            // Disconnected
            if (NetworkHandler::s_GetConnectedFlag() == false)
            {
                // Update the info 
                Display::s_DrawInfoDisplayMux(p_messageHandler);
                return; // Exit out
            }

        }
        // We check if there are any messages that are needed to be sent
        // if messageHandler has any messages on the queue then we should send them

        if (p_messageHandler->m_GetSizeofSendQueue() > 0)
        {
            auto networkMessage = p_messageHandler->m_GetMessageFromSendQueue();
            p_networkHandler->m_Send(networkMessage->msgType, networkMessage->message);
        }

        // Here we also deal with any network errors

        // Return threads
        if (returnThreads)
        {
            p_networkHandler->m_Close();
            Display::s_DrawInfoDisplayMux(p_messageHandler);
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(msThreadDelay));
    }
}


void DrawThreadMethod(void)
{
    Display::s_ClearTerminal();
    Display::s_Draw(p_messageHandler);
    short oldColumn, oldRow;
    Display::s_GetConsoleMaxCoords(oldColumn, oldRow);
    while (true)
    {
        short column, row;
        Display::s_GetConsoleMaxCoords(column, row);

        if (oldColumn != column || oldRow != row)
        {
            Log::s_GetInstance()->m_LogWrite("Display::s_Draw()", "Terminal resolution changed, redrawing. ", column, "x", row);
            Display::s_ClearTerminal();
            Display::s_Draw(p_messageHandler);
            oldColumn = column; oldRow = row;
        }
            
        std::this_thread::sleep_for(std::chrono::milliseconds(msThreadDelay));
        if (returnThreads) {return;}
    }
}


int main()
{
    // Thread to handle the user input at all times
    p_messageHandler = new MessageHandler();
    // Lifetime of all threads is managed by the main thread
    std::thread messageThread(MessageHandler::m_HandleInput, p_messageHandler);

    Display::s_SetTerminalModeRaw();

    // Another thread needed for Drawing to the screen
    std::thread drawThread(DrawThreadMethod);

    // Another thread needed for handing of network traffic.
    std::thread networkThread(HandleNetwork);

    // Cleanup
    messageThread.join();

    // If the return threads flag has not been enabled then we can enable it here
    if (!returnThreads) returnThreads = true;

    drawThread.join();
    networkThread.join();

    // Free messageHandler and networkHandler
    delete(p_messageHandler);
    delete(p_networkHandler);
    
    // Reset the terminal mode before we exit
    Display::s_SetTerminalModeReset();
    return 0;
}

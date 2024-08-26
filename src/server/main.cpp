#include "logging.hpp"
#include "network/networkHandler.hpp"

#include <thread>
#include <memory>
#include <atomic>

#include <iostream>
#include <conio.h> // _kbhit(), _getch()


NetworkHandler* p_networkHandler;

std::atomic<int> returnThreads{0};

const std::string port = "27011";

// UpdateRate
#define THREADUPDATERATE 60 // hz
constexpr int msThreadDelay = 1000/THREADUPDATERATE;

// Should run a certain amount of updates a second (60hz)
// 1000/60 ms wait per cycle. 
void HandleNetwork(void)
{
    // Create socket
    // Set listen
    // 
    // Non blocking accept, we check if there are any
    // If so spool up async connection 
    //      in the async call, attempt to make the socket blocking to recieve the name packet. (Save cpu cycles)
    //      after the socket has been processed, we can switch it back to non-blocking
    //
    // Check each socket if there is incoming connection.
    //
    // Yes, we can broadcast
    
    // Check for incoming connections

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    p_networkHandler = new NetworkHandler();
    p_networkHandler->m_Create(port);
    p_networkHandler->m_Listen(10);

    int lastCheckedConnUsers = 0;
    std::vector<spNetworkedUser> connectedUsersCopy = p_networkHandler->m_GetNetworkedUsers();

    while(true)
    {
        p_networkHandler->m_Accept();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        int currentUsers = p_networkHandler->m_GetNetworkedUsersCount();
        // We have had new users join, update the connectedUsersCopy list
        if (currentUsers != lastCheckedConnUsers)
        {
            connectedUsersCopy = p_networkHandler->m_GetNetworkedUsers();
        }

        // Check for incoming messages
        for (auto& user : connectedUsersCopy)
        {
            std::string message = p_networkHandler->m_RecieveMessage(user);
            // User disconnected
            if (message == "")
            {
                // TODO p_networkHandler->m_DisconnectUser(user);
            }
            else
            {
                p_networkHandler->m_BroadcastMessage(user, message);
            }
        }


        if (returnThreads)
        {
            // Shutdown connections and return
            
            return;
        }
    }

    // p_networkHandler = new NetworkHandler();

    // p_networkHandler->m_Create(hostname, port);
    
    // // Keep trying to connect until we do
    // while (true)
    // {
    //     if(p_networkHandler->m_Connect())
    //         break;
    //     std::this_thread::sleep_for(std::chrono::milliseconds(msThreadDelay));
    // }
    // // Recv and send any data that is available
    // while (true)
    // {
    //     // Recv message and add to the message display
    //     std::string recvMsg = p_networkHandler->m_RecieveMessages();
    //     if (recvMsg != "")
    //     {
    //         p_messageHandler->m_PushMessageToDisplay(recvMsg);
    //         Display::s_DrawMessageDisplay(p_messageHandler);
    //     }
    //     // We check if there are any messages that are needed to be sent
    //     // if messageHandler has any messages on the queue then we should send them

    //     if (p_messageHandler->m_GetSizeofSendQueue() > 0)
    //     {
    //         p_networkHandler->m_Send(p_messageHandler->m_GetMessageFromSendQueue());
    //     }

    //     // Here we also deal with any network errors

    //     // Return threads
    //     if (returnThreads)
    //     {
    //         p_networkHandler->m_Close();
    //         return;
    //     }
    //     std::this_thread::sleep_for(std::chrono::milliseconds(msThreadDelay));
    // }
}

int main()
{
    // Server control loop
    // 
    // 1 Main thread that spools up the network handler thread.
    // Other thread listens for the input to close it (esc key)
    //
    // Network handler.
    // Do we have incoming connection request?
    //    - Async task - Get name packet and add to connected clients list
    // Do we have any connected clients?
    //    - For every client, do they have a message to send us?
    //         - If so, we broadcast the message to all other connected clients, including the one who sent it to us
    // 

    // Another thread needed for handing of network traffic.
    std::thread networkThread(HandleNetwork);
    
    // Wait for input
    while (true)
    {
        char c;
        if (_kbhit()) {  // Check if a key is pressed
            c = _getch();  // Read the key press without buffering (no await enter key)
            if (c == 27) // Esc key pressed
            {
                Log::s_GetInstance()->m_LogWrite("Main thread", "ESC key pressed, closing server.");
                break;
            }
        }
    }
    // Indicate to thread to return
    returnThreads^=1;
    p_networkHandler->m_Shutdown();
    networkThread.join();

    // Free networkHandler
    delete(p_networkHandler);
    
    return 0;
}

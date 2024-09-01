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

    p_networkHandler = new NetworkHandler();
    p_networkHandler->m_Create(port);
    p_networkHandler->m_Listen(10);

    int lastCheckedConnUsers = 0;
    std::vector<spNetworkedUser> connectedUsersCopy = p_networkHandler->m_GetNetworkedUsers();

    while(true)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(msThreadDelay));

        p_networkHandler->m_Accept();

        int currentUsers = p_networkHandler->m_GetNetworkedUsersCount();
        // We have had new users join, update the connectedUsersCopy list
        if (currentUsers != lastCheckedConnUsers)
        {
            Log::s_GetInstance()->m_LogWrite("Thread HandleNetwork()", "Number of conn users changed: Curr:", currentUsers, " last value: ", lastCheckedConnUsers);
            connectedUsersCopy = p_networkHandler->m_GetNetworkedUsers();
            lastCheckedConnUsers = currentUsers;
        }

        int i = 0;
        // Check for incoming messages
        for (auto& user : connectedUsersCopy)
        {
            std::string message;
            // If we have a message, the string will be set
            if (p_networkHandler->m_ReceiveMessage(user, message))
            {
                // If we recieve a message and return true we can assume its a standard msg
                p_networkHandler->m_BroadcastMessage(MessageType::MESSAGE, user, message);
            }
            i++;
        }

        if (returnThreads)
        {
            // Shutdown connections and return
            return;
        }
    }
}

int main()
{
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
        std::this_thread::sleep_for(std::chrono::milliseconds(msThreadDelay));
    }
    // Indicate to thread to return
    returnThreads^=1;
    p_networkHandler->m_Shutdown();
    networkThread.join();
    Log::s_GetInstance()->m_LogWrite("Main thread", "Network thread shutdown.");

    // Free networkHandler
    delete(p_networkHandler);
    
    Log::s_GetInstance()->m_LogWrite("Main thread", "exit 0");   
    return 0;
}

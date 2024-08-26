// Networking headers
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include <string>
#include <memory>
#include <vector>
#include <mutex>
#include <cstring>

// Network specific macros
#define ISVALIDSOCKET(s) ((s) != INVALID_SOCKET)
#define CLOSESOCKET(s) closesocket(s)
#define GETSOCKETERRNO() (WSAGetLastError())

// Chat related
#define MAXALIASSIZE 10



class NetworkedUser
{
private:
    SOCKET m_userSocket;
    std::string m_alias;
    time_t connectionTime;
    char address[NI_MAXHOST];

public:
    NetworkedUser(SOCKET sock_in, std::string name_in, time_t time_in, const char addr_in[NI_MAXHOST]) : 
        m_userSocket(sock_in), m_alias(name_in), connectionTime(time_in)
    {
        std::strcpy(address, addr_in);
    }

    SOCKET m_GetUserSocket(void) const 
    {
        return m_userSocket;
    }

    std::string m_GetUserAlias(void) const 
    {
        return m_alias;
    }

    const char* m_GetUserAddress(void) const 
    {
        return address;
    }

};

// Shared pointer of NetworkedUser
using spNetworkedUser = std::shared_ptr<NetworkedUser>;

class NetworkHandler
{
private:
    struct addrinfo* peer_address;

    std::vector<spNetworkedUser> connectedUsers;
    std::mutex connectedUserVectorMutex;

    void m_AsyncNewConnectionHandle(SOCKET userSocket, const char address[NI_MAXHOST]);

    SOCKET m_serverSocket;


public:

    // Threadsafe actions on connectedUsers vector:
    void m_AddNetworkedUser(spNetworkedUser user);

    std::vector<spNetworkedUser> m_GetNetworkedUsers(void);

    int m_GetNetworkedUsersCount(void);
    
    void m_ClearNetworkedUserVector(void);

    // Needs to be thread safe
    bool m_IsUsernameTaken(const std::string& username);

    // @brief Sets any socket as either blocking or non-blocking
    // @param blocking boolean either true for blocking or false for non-blocking
    void SetSocketBlocking(bool blocking, SOCKET socket);

    // @brief Creates the socket and policies
    // @param port port number string
    // @return bool - success
    bool m_Create(std::string port);

    // @brief will set the socket to listen to n amount of connections
    // @param connections will set the number of users the server will allow to queue to connect at any one point
    // @return bool - success
    bool m_Listen(int connections);

    // @brief Accept any incoming connections
    // @return bool - success
    bool m_Accept(void);

    // @brief Check for a message from a user, if there is one we can recieve it
    // @param connectedUser is the handle to check the connected user
    // @return string - recieved message, if message is empty then connection is closed
    std::string m_RecieveMessage(spNetworkedUser connectedUser);

    // @brief Send a message to all connected users
    // @param Sender NetworkedUser struct of the users sending the message
    // @param message string to send
    // @return bool - success
    bool m_BroadcastMessage(spNetworkedUser sender, std::string message);

    // @brief Send message to certain connected user
    // @param connectedUser is who to send the message to
    // @param message is the message
    // @return bool - success
    bool m_Send(SOCKET recipient, std::string message);
    bool m_Send(spNetworkedUser recipient, std::string message);

    bool m_DisconnectUser(spNetworkedUser connectedUser);

    // @brief Closes all connections and clean up
    // @return bool - success
    bool m_Shutdown(void);
};

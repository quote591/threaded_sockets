// Networking headers
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include <string>

#define ISVALIDSOCKET(s) ((s) != INVALID_SOCKET)
#define CLOSESOCKET(s) closesocket(s)
#define GETSOCKETERRNO() (WSAGetLastError())

struct NetworkedUser
{
    std::string m_alias;
    SOCKET m_userSocket;
};


class NetworkHandler
{
private:
    SOCKET socket_peer;
    struct addrinfo* peer_address;


public:
    // @brief Creates the socket and policies
    // @param hostName ipAddress
    // @param port port number string
    // @return bool - success
    bool m_Create(std::string hostName, std::string port);

    // @brief Accept any incoming connections
    // @return bool - success
    bool m_Accept(void);

    // @brief Checks if any messages are waiting to be read
    // @return If there are messages then return a copy of them
    std::string m_RecieveMessages(void);

    // @brief Send a message to the connected socket
    // @param Copy of the message
    // @return bool - success
    bool m_Send(std::string msg);

    // @brief Close the established connection
    // @return bool - success
    bool m_Close(void);
};

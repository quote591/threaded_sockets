// Networking headers
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include <string>
#include <mutex>
#include <atomic>

#define ISVALIDSOCKET(s) ((s) != INVALID_SOCKET)
#define CLOSESOCKET(s) closesocket(s)
#define GETSOCKETERRNO() (WSAGetLastError())

// 2^16 - 40. 
// 40 is the minimum size of the tcp packet. (TODO check this, header size can change)
// 2 is our overhead of the packet 2 bytes for size
constexpr unsigned int MAXTCPPAYLOAD = 65535-40-2;

// Forward decleration
class MessageHandler;

struct Packet
{
    Packet() = default;
    Packet(unsigned char messageTypeIn, std::string messageIn) : 
           msgType(messageTypeIn), message(messageIn) {}

    unsigned char msgType;
    std::string message;
};

namespace MessageType{

    enum MessageType: unsigned char
    {
        // Alias
        ALIASSET,   // Client <-> Server Requesting and Setting alias 
        ALIASACK,   // Server -> Client Accept alias
        ALIASDNY,   // Server -> Client Reject alias

        // General message
        MESSAGE,    // Client <-> Server

        // Server info
        CONNUSERS,  // Server -> Client Number of connected users

    };

    std::string GetMessageType(unsigned char msgbyte);

}

class NetworkHandler
{
private:
    SOCKET socket_peer;
    struct addrinfo* peer_address;

    static bool bConnectedFlag;
    static std::mutex connectedFlagMutex;

public:
    static std::atomic<int> m_knownConnectedUsers;
    

    /// @brief Creates the socket and policies
    /// @param hostName ipAddress
    /// @param port port number string
    /// @return bool - success
    bool m_Create(std::string hostName, std::string port);


    /// @brief Establishes the network connection
    /// @return bool - success
    bool m_Connect(void);


    /// @brief Check for a message from a user, if there is one we can recieve it
    /// @param messageOut is the returned message, will only be set if method return true
    /// @param p_messageHandler pointer to message handler
    /// @return bool - if there was a message to print
    bool m_ReceiveMessage(std::string& messageOut, MessageHandler* p_messageHandler);


    /// @brief Send a message to the connected socket
    /// @param msgType Type of messsage
    /// @param msg message to send
    /// @return bool - success
    bool m_Send(unsigned char msgType, const std::string& msg);


    /// @brief Wrapper for recv()
    /// @param connection Connected user struct to recieve the data (can be nullptr)
    /// @param incomingPacketOut Struct passed by ref. Will set the data if method return true
    /// @return bool - success
    bool m_Recv(SOCKET connection, Packet& incomingPacketOut);


    /// @brief Close the established connection
    /// @return bool - success
    bool m_Close(void);


    /// @brief Set the connection boolean
    /// @param Value the boolean to set the flag
    static void s_SetConnectedFlag(bool value);


    /// @brief Get the value of the connection boolean
    /// @return Wether the socket is connected
    static bool s_GetConnectedFlag(void);

};

#include "encryption.hpp"

// Networking headers
#ifdef _WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#endif

#include <string>
#include <memory>
#include <vector>
#include <mutex>
#include <cstring>
#include <future>

// Network specific macros
#define ISVALIDSOCKET(s) ((s) != INVALID_SOCKET)
#define CLOSESOCKET(s) closesocket(s)
#define GETSOCKETERRNO() (WSAGetLastError())

// 2^16 - 40. 
// 40 is the minimum size of the tcp packet
// 2 is our overhead of the packet 2 bytes for size
constexpr unsigned int MAXTCPPAYLOAD = 65535-40-2;

// Packet offsets
constexpr int SIGNATURE_OFFSET = 1;
constexpr int IV_OFFSET = SIGNATURE_OFFSET + SHA256_AES_ENCRYPTED_BYTES;
constexpr int PAYLOAD_OFFSET = IV_OFFSET + AESIV_SIZE_BYTES;
constexpr unsigned int TYPEANDSIZEBYTES = 3;


namespace MessageType{

    enum MessageType: unsigned char
    {
        // Alias
        ALIASSET,   // Client <-> Server Requesting and Setting alias 
        ALIASACK,   // Server -> Client Accept alias. Sends accepted username
        ALIASDNY,   // Server -> Client Reject alias. Send reason why

        // General message
        MESSAGE,    // Client <-> Server

        // Server info
        CONNUSERS,  // Server -> Client Number of connected users

        // Secure connection
        SECURECON, // Client -> Server Sends their DH pub Key, Server -> Client responds with their own DH pub Key 
    };

    std::string GetMessageType(unsigned char msgByte);
}


class Packet
{
private:
    unsigned char msgType;
    std::unique_ptr<unsigned char[]> bytes;
    size_t bytesSize;
public:
    Packet() = default;
    Packet(unsigned char messageType, unsigned char* data, size_t dataSize) : msgType(messageType), bytesSize(dataSize)
    {
        bytes = std::make_unique<unsigned char[]>(dataSize);
        std::memcpy(bytes.get(), data, dataSize);
    }
    Packet(unsigned char messageType, const std::string& msg) : msgType(messageType), bytesSize(msg.size())
    {
        bytes = std::make_unique<unsigned char[]>(msg.size());
        std::memcpy(bytes.get(), msg.c_str(), msg.size());
    }

    unsigned char GetMsgType(void) const
    {
        return msgType;
    }

    size_t GetBytesSize(void) const
    {
        return bytesSize;
    }

    unsigned char* GetBytes(void) const
    {
        return bytes.get();
    }

    char* GetChars(void) const
    {
        return reinterpret_cast<char*>(bytes.get());
    }

    void SetMessageType(const unsigned char type)
    {
        msgType = type;
    }

    void SetBytes(unsigned char* data, size_t dataSize)
    {
        bytes = std::make_unique<unsigned char[]>(dataSize);
        std::memcpy(bytes.get(), data, dataSize);
    }
};


class NetworkedUser
{
private:
    SOCKET m_userSocket;
    std::string m_alias;
    time_t m_connectionTime;
    char m_address[NI_MAXHOST];
    std::unique_ptr<Encryption> m_userEncryption;

public:
    NetworkedUser() = default;

    NetworkedUser(SOCKET sock_in, std::string name_in, time_t time_in, const char addr_in[NI_MAXHOST]) : 
        m_userSocket(sock_in), m_alias(name_in), m_connectionTime(time_in)
    {
        std::strcpy(m_address, addr_in);
    }

    // Builders
    NetworkedUser* m_SetSocket(const SOCKET sock)
    {
        m_userSocket = sock;
        return this;
    }

    NetworkedUser* m_SetAlias(const std::string& alias)
    {
        m_alias = alias;
        return this;
    }

    NetworkedUser* m_SetConnectionTime(const time_t& connectionTime)
    {
        m_connectionTime = connectionTime;
        return this;
    }

    NetworkedUser* m_SetAddress(const char address[NI_MAXHOST])
    {
        std::strcpy(m_address, address);
        return this;
    }

    NetworkedUser* m_SetEncryptionObject(std::unique_ptr<Encryption>& encryptionObj)
    {
        m_userEncryption = std::move(encryptionObj);
        return this;
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
        return m_address;
    }

    Encryption* m_GetEncryptionHandle(void) const
    {
        return m_userEncryption.get();
    }
};


// Shared pointer of NetworkedUser
using spNetworkedUser = std::shared_ptr<NetworkedUser>;

class NetworkHandler
{
private:
    struct addrinfo* peer_address;
    SOCKET m_serverSocket;

    std::mutex connectedUserVectorMutex;
    std::vector<spNetworkedUser> connectedUsers;

    std::mutex asyncConnectionJobsMutex;
    std::vector<std::future<void>> asyncConnectionJobs;


    /// @brief Handle new connection (accept) asyncronously
    /// @param userSocket socket handle
    /// @param address network address
    void m_AsyncNewConnectionHandle(SOCKET userSocket, const char address[NI_MAXHOST]);

public:

    /// @brief Attempt to add a new user. Will reject if the username is taken
    /// @param user The shared pointer of the new user we are attempting to add
    /// @return bool - success (failed means username taken)
    bool m_AttemptAddNetworkedUser(spNetworkedUser user);


    /// @brief Return a copy of the connected user vector
    /// @return vector copy of connected users
    std::vector<spNetworkedUser> m_GetNetworkedUsers(void);


    /// @brief Get the number of connected users (with registered usernames)
    /// @return int - number of connected users
    int m_GetNetworkedUsersCount(void);
    

    /// @brief Clear the connected user vector thread safe
    void m_ClearNetworkedUserVector(void);

    
    /// @brief Holds the future return of a std::asnyc
    /// @param job the std::async return to be passed
    void m_AddAsyncConnectionJob(std::future<void>&& job);


    /// @brief Sets any socket as either blocking or non-blocking
    /// @param blocking boolean either true for blocking or false for non-blocking
    void SetSocketBlocking(bool blocking, SOCKET socket);


    /// @brief Creates the socket and policies
    /// @param port port number string
    /// @return bool - success
    bool m_Create(std::string port);


    /// @brief will set the socket to listen to n amount of connections
    /// @param connections will set the number of users the server will allow to queue to connect at any one point
    /// @return bool - success
    bool m_Listen(int connections);


    /// @brief Accept any incoming connections
    /// @return bool - success
    bool m_Accept(void);


    /// @brief Check for a message from a user, if there is one we can recieve it
    /// @param connectedUser is the handle to check the connected user
    /// @param messageOut is the returned message, will only be set if method return true
    /// @return bool - if there was a message
    bool m_ReceiveMessage(spNetworkedUser connectedUser, std::string& messageOut);


    /// @brief Send a message to all connected users
    /// @param messageType Type of messsage
    /// @param Sender NetworkedUser struct of the users sending the message
    /// @param message string to send
    /// @return bool - success
    bool m_BroadcastMessage(unsigned char messageType, spNetworkedUser sender, std::string message);


    /// @brief Send message to certain connected user. The only method that will call Ws2 send()
    /// @param messageType Type of messsage
    /// @param recipient Socket to send the message to
    /// @param data Bytes to send
    /// @param dataSize Number of bytes to send
    /// @param message Message to send as std::string
    /// @return Bool - success
    bool m_Send(SOCKET recipient, Encryption* upEncryptionHandle, const unsigned char messageType, const unsigned char* data, const size_t dataSize, bool encrypted = true);
    inline bool m_Send(SOCKET recipient, Encryption* upEncryptionHandle, unsigned char messageType, const std::string& message, bool encrypted = true);


    /// @brief Wrapper for recv()
    /// @param sender Connected user struct to recieve the data (can be nullptr)
    /// @param senderSock Non-connected user to recieve the data like in accept (can be nullptr)
    /// @param upEncryptionHandle 
    /// @param incomingPacketOut Struct passed by ref. Will set the data if method return true
    /// @param blocking Flag for if the sockets are set as blocking
    /// @return bool - success
    bool m_Recv(spNetworkedUser sender, SOCKET* senderSock, Encryption* upEncryptionHandle, Packet& incomingPacketOut, bool blocking, bool encrypted = true);


    /// @brief Disconnect a connected user
    /// @param userToDisconnect Connected user struct
    /// @return bool - success
    bool m_DisconnectUser(const spNetworkedUser userToDisconnect);


    /// @brief Closes all connections and clean up
    /// @return bool - success
    bool m_Shutdown(void);
};

inline bool NetworkHandler::m_Send(SOCKET recipient, Encryption* upEncryptionHandle, unsigned char messageType, const std::string& message, bool encrypted)
{
    return this->m_Send(recipient, upEncryptionHandle, messageType, reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), encrypted);
}

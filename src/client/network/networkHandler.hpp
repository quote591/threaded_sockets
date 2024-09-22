// Networking headers
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include "encryption.hpp"

#include <string>
#include <mutex>
#include <atomic>
#include <cstring>
#include <memory>

#define ISVALIDSOCKET(s) ((s) != INVALID_SOCKET)
#define CLOSESOCKET(s) closesocket(s)
#define GETSOCKETERRNO() (WSAGetLastError())

// Packet offsets
constexpr int SIGNATURE_OFFSET = 1;
constexpr int IV_OFFSET = SIGNATURE_OFFSET + SHA256_AES_ENCRYPTED_BYTES;
constexpr int PAYLOAD_OFFSET = IV_OFFSET + AESIV_SIZE_BYTES;
constexpr unsigned int TYPEANDSIZEBYTES = 3;


// 2^16 - 40. 
// 40 is the minimum size of the tcp packet. (TODO check this, header size can change)
// 2 is our overhead of the packet 2 bytes for size
constexpr unsigned int MAXTCPPAYLOAD = 65535-40-2;


// Forward decleration
class MessageHandler;


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

    std::string GetString(void) const
    {
        return std::string(reinterpret_cast<char*>(bytes.get()), bytesSize);
    }

    void SetMessageType(const unsigned char type)
    {
        msgType = type;
    }

    void SetBytes(unsigned char* data, size_t dataSize)
    {
        bytes = std::make_unique<unsigned char[]>(dataSize);
        bytesSize = dataSize;
        std::memcpy(bytes.get(), data, dataSize);
    }
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

        // Secure connection
        SECURECON, // Client -> Server Sends their DH pub Key, Server -> Client responds with their own DH pub Key 

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

    std::unique_ptr<Encryption> upEncryptionHandle;

public:
    static std::atomic<int> m_knownConnectedUsers;
    
    NetworkHandler();

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
    /// @param msgType Enum to indicate type of message
    /// @param data Bytes to send to socket
    /// @param dataSize Number of bytes to send to the socket
    /// @param encrypted Wether the message is encryped or not
    /// @param msg Message to send (std::string)
    /// @return Bool - success
    bool m_Send(const unsigned char msgType, const unsigned char* data, const size_t dataSize, bool encrypted = true);
    inline bool m_Send(const unsigned char msgType, const std::string& msg, bool encrypted = true);


    /// @brief Wrapper for recv()
    /// @param connection Connected user struct to recieve the data (can be nullptr)
    /// @param incomingPacketOut Struct passed by ref. Will set the data if method return true
    /// @param encrypted Wether the incoming packet is expected to be encrypted or not
    /// @return bool - success
    bool m_Recv(SOCKET connection, Packet& incomingPacketOut, bool encrypted = true);


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

// Inline definitions
inline bool NetworkHandler::m_Send(const unsigned char msgType, const std::string& msg, bool encrypted)
{
    return this->m_Send(msgType, reinterpret_cast<const unsigned char*>(msg.c_str()), msg.size(), encrypted);
}

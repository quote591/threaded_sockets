#include "networkHandler.hpp"
#include "../logging.hpp"
#include "../messageHandler.hpp"
#include "../display.hpp"

#include <sstream>
#include <cassert>
#include <cstring>
#include <memory>

// Static declares
bool NetworkHandler::bConnectedFlag = false;
std::mutex NetworkHandler::connectedFlagMutex;
std::atomic<int> NetworkHandler::m_knownConnectedUsers = 0;


std::string MessageType::GetMessageType(unsigned char msgbyte)
{
    switch (msgbyte)
    {
        case ALIASSET:  return "Alias set";
        case ALIASACK:  return "Alias acknowledge";
        case ALIASDNY:  return "Alias deny";
        case MESSAGE:   return "General message";
        case CONNUSERS: return "Connected users control";
        default:        return "Unknown";
    }
}


NetworkHandler::NetworkHandler()
{
    upEncryptionHandler = std::make_unique<Encryption>();
}


bool NetworkHandler::m_Create(std::string hostName, std::string port)
{
    // Not filled in 
    if (hostName.c_str() == NULL || port.c_str() == NULL){
        return false;
    }

    // Set windows socket version
#ifdef _WIN32
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)) {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", "error: WSAStartup() failed to initalize.");
        return false;
    }
#endif

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    // TCP UDP(SOCK_DGRAM)
    hints.ai_socktype = SOCK_STREAM;
    // struct addrinfo* peer_address;
    if (getaddrinfo(hostName.c_str(), port.c_str(), &hints, &peer_address)) {
        std::stringstream getAddrInfoSS; getAddrInfoSS << "error: getaddrinfo() failed. Errno " << GETSOCKETERRNO() << ")";
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", getAddrInfoSS.str());
        return false;
    }

    // Again variable arrays potentially
    char address_buffer[100];
    char service_buffer[100];
    getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen,
        address_buffer, sizeof(address_buffer),
        service_buffer, sizeof(service_buffer),
        NI_NUMERICHOST);

    std::stringstream getNameInfoSS; getNameInfoSS << "Remote address: " << address_buffer << ":" << service_buffer;
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", getNameInfoSS.str());

    // Create socket
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", "Creating socket...");

    socket_peer = socket(peer_address->ai_family,
        peer_address->ai_socktype, peer_address->ai_protocol);
    if (!ISVALIDSOCKET(socket_peer)) {
        std::stringstream isValidSocketSS; isValidSocketSS << "error: socket() failed. errno: (" << GETSOCKETERRNO() << ")";
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", isValidSocketSS.str());
        WSACleanup();
        return false;
    }


    return true;
}


bool NetworkHandler::m_Connect()
{
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Connect()", "Attempting to connect...");

    // Connect
    
    if (connect(socket_peer,
        peer_address->ai_addr, peer_address->ai_addrlen)) {
        
        std::stringstream connectSS; connectSS << "connect() failed errno:(" << GETSOCKETERRNO() << ")";
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Connect()", connectSS.str());
        return false;
    }
    
    // Setup encryption keys
    unsigned char publicKey[DH_PUBLICKEY_SIZE_BYTES];
    upEncryptionHandler->GetDHPubKey(publicKey);
    this->m_Send(MessageType::SECURECON, publicKey, DH_PUBLICKEY_SIZE_BYTES);
    
    // Recieve the peer public key
    Packet recievedPacket;
    do{
        this->m_Recv(socket_peer, recievedPacket);
    } while (recievedPacket.GetMsgType() != MessageType::SECURECON);
 
    // Set our public peer key then derive secret key
    upEncryptionHandler->SetDHPublicPeer(*recievedPacket.GetBytes(), recievedPacket.GetBytesSize());    
    upEncryptionHandler->DeriveSecretKey();

    freeaddrinfo(peer_address);
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Connect()", "Connected.");
    NetworkHandler::s_SetConnectedFlag(true);

    // Set socket into non-blocking mode
    // We enable it after the connect call as we do not want 
    u_long iMode = 1;
    std::string ioctlsocketMsg;
    if (ioctlsocket(socket_peer, FIONBIO, &iMode) != NO_ERROR)
        ioctlsocketMsg = "Error setting socket as non-blocking";
    else
        ioctlsocketMsg = "Set socket into non-blocking mode";
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Connect()", ioctlsocketMsg);

    return true;
}


bool NetworkHandler::m_ReceiveMessage(std::string& messageOut, MessageHandler* p_messageHandler)
{
    WSAPOLLFD fds[1];
    fds[0].fd = socket_peer;
    fds[0].events = POLLRDNORM;  

    const int POLL_TIMEOUT_MS = 1;
    int retCode = WSAPoll(fds, 1, POLL_TIMEOUT_MS);
    if (retCode == SOCKET_ERROR)
    {
        std::stringstream recvSS; recvSS << "Error occured WSAPoll(): " << errno;
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessages()", recvSS.str());
    }

    else if (retCode != 0)
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_ReceiveMessage()", "Packet available");

        Packet networkPacket;
        if (!m_Recv(socket_peer, networkPacket))
        {
            Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_ReceiveMessage()", "Error occured in m_Recv()");
            NetworkHandler::s_SetConnectedFlag(false);
            return false;
        }

        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_ReceiveMessage()", "Packet type (", MessageType::GetMessageType(networkPacket.GetMsgType()), ") : ", networkPacket.GetBytes());
        
        // We now handle the message accordingly
        switch (networkPacket.GetMsgType())
        {
            // Print out message
            case MessageType::ALIASACK:
            {
                p_messageHandler->s_SetUserAlias(networkPacket.GetChars());
                MessageHandler::m_aliasSet = true;
                messageOut = "You've joined the chat room.";
                return true;
            }

            case MessageType::ALIASSET:
            case MessageType::ALIASDNY:
            case MessageType::MESSAGE:
            {
                messageOut = std::string(networkPacket.GetChars());
                return true;
            }

            case MessageType::CONNUSERS:
            {
                try{
                    NetworkHandler::m_knownConnectedUsers = std::stoi(networkPacket.GetChars());
                }
                catch (const std::invalid_argument& e)
                {
                    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_ReceiveMessage()", "Error: Invalid number of connected users: ", networkPacket.GetChars());
                    return false;
                }

                Display::s_DrawInfoDisplayMux(p_messageHandler);
                return false;
            }
            default:
            {
                Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_ReceiveMessage()", "Invalid packet type: ", MessageType::GetMessageType(networkPacket.GetMsgType()), "(", (int)networkPacket.GetMsgType(), ")");
                return false;
            }
        }
        // false
    }
    return false;
}


bool NetworkHandler::m_Send(const unsigned char msgType, const std::string& msg)
{
    // 1 for the message type, size of the 2 bytes that say size is not included
    std::uint16_t payloadSize = 1 + msg.size();
    assert(payloadSize < MAXTCPPAYLOAD);

    // Turn the integer into the two bytes to be written
    std::uint8_t payloadSizeBytes[2] = {static_cast<std::uint8_t>(payloadSize >> 8), static_cast<std::uint8_t>(payloadSize & 0xFF)};

    std::string message = std::string(reinterpret_cast<char*>(payloadSizeBytes), 2) + static_cast<char>(msgType) + msg;

    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Send()", "Send: '", msg, "' (", msg.size(), " bytes)");
    return send(socket_peer, message.c_str(), message.size(), 0);
}


bool NetworkHandler::m_Send(const unsigned char msgType, const unsigned char* data, const size_t dataSize)
{
    try
    {
        // Setup encryption hashes, IVs and payload
        unsigned char IV[AESIV_SIZE_BYTES];
        if (!upEncryptionHandler->GenerateIV(IV))
            throw ("Generate IV failed.");

        std::unique_ptr<unsigned char[]> encryptedPayload;
        int encryptedPayloadSize = upEncryptionHandler->EncryptData(*data, dataSize, *IV, encryptedPayload);
        if (encryptedPayloadSize == -1)
            throw ("EncryptData failed.");
        
        // Create buffer for IV and enc payload to generate signature for
        std::unique_ptr<unsigned char[]> packetIVPayload = std::make_unique<unsigned char[]>(AESIV_SIZE_BYTES + encryptedPayloadSize);
        std::memcpy(packetIVPayload.get(), IV, 16);
        std::memcpy(packetIVPayload.get() + 16, encryptedPayload.get(), encryptedPayloadSize);

        unsigned char signature[SHA256_AES_ENCRYPTED_BYTES];
        if(!upEncryptionHandler->CreatePacketSig(*packetIVPayload.get(), AESIV_SIZE_BYTES + encryptedPayloadSize, *IV, signature))
            throw ("Create packet signature failed.");

        // 1 is the message type
        std::uint16_t payloadSize = 1 + SHA256_AES_ENCRYPTED_BYTES + AESIV_SIZE_BYTES + encryptedPayloadSize;
        // Turn the 16 bit integer into two bytes 0-65535
        std::uint8_t payloadSizeBytes[2] = {static_cast<std::uint8_t>(payloadSize >> 8), static_cast<std::uint8_t>(payloadSize & 0xFF)};
        
        // +2 for size bytes
        std::unique_ptr<unsigned char[]> dataToSend = std::make_unique<unsigned char[]>(payloadSize+2);
        std::memcpy(dataToSend.get(), payloadSizeBytes, 2);                             // Size data
        std::memcpy(dataToSend.get()+2, &msgType, 1);                                   // Message type data
        std::memcpy(dataToSend.get()+3, signature, SHA256_AES_ENCRYPTED_BYTES);         // Encrypted Signature
        std::memcpy(dataToSend.get()+3+SHA256_AES_ENCRYPTED_BYTES, 
                    packetIVPayload.get(), AESIV_SIZE_BYTES + encryptedPayloadSize);    // Encrypted Signature

        // +2 for the bytes for size aswell as the data and msgType byte
        return send(socket_peer, reinterpret_cast<const char*>(dataToSend.get()), payloadSize+2, 0);
    }
    catch(const char* err)
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Send", "Error: ", err);
        return false;
    }
}


bool NetworkHandler::m_Recv(SOCKET connection, Packet &incomingPacketOut)
{
    std::uint8_t packetSizeBuffer[2];
    std::uint8_t* packetBuffer = nullptr;

    try
    {
        // Get packet size
        int recvLengthSize = recv(connection, reinterpret_cast<char*>(packetSizeBuffer), sizeof(packetSizeBuffer), 0);

        if (recvLengthSize == -1)
        {
            int error = GETSOCKETERRNO();
            if (error == WSAECONNRESET)
                throw ("Socket was forcefully reset by connected peer.");

        }
        else if (recvLengthSize == 0)
            throw ("recv length 0: connection dropped.");

        std::uint16_t packetSize;
        packetSize = (static_cast<std::uint16_t>(packetSizeBuffer[0]) << 8) + static_cast<std::uint16_t>(packetSizeBuffer[1]);
        
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Recv", "Packet size recieved: ", packetSize);
        // Once we have the message length we can get the packet
        packetBuffer = (std::uint8_t*)malloc(packetSize);

        int recvPacketSize = recv(connection, reinterpret_cast<char*>(packetBuffer), packetSize, 0);
        if (recvPacketSize == -1)
        {
            int error = GETSOCKETERRNO();
            if (error == WSAECONNRESET)
                throw ("Socket was forcefully reset by connected peer.");
        }
        else if (recvLengthSize == 0)
            throw ("recv packet 0: connection dropped.");

        incomingPacketOut.SetMessageType(packetBuffer[0]);
        incomingPacketOut.SetBytes(packetBuffer+1, recvPacketSize-1);
    }
    catch (const char* err)
    {
        if (packetBuffer != nullptr)
            free(packetBuffer);
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Recv", "Error: ", err);
    }

    free(packetBuffer);
    return true;
}


bool NetworkHandler::m_Close(void)
{
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Close()", "Closing socket.");
    CLOSESOCKET(socket_peer);

#ifdef _WIN32
    WSACleanup();
#endif

    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Close()", "Socket closed.");
    NetworkHandler::s_SetConnectedFlag(false);
    return true;
}


void NetworkHandler::s_SetConnectedFlag(bool value)
{
    std::lock_guard<std::mutex> lock(connectedFlagMutex);
    bConnectedFlag = value;
}


bool NetworkHandler::s_GetConnectedFlag(void)
{
    std::lock_guard<std::mutex> lock(connectedFlagMutex);
    return bConnectedFlag;
}

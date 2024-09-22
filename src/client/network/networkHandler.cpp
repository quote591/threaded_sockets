#include "networkHandler.hpp"
#include "../logging.hpp"
#include "../messageHandler.hpp"
#include "../display.hpp"

#include <sstream>
#include <cassert>
#include <cstring>

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
    upEncryptionHandle = std::make_unique<Encryption>();
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
    try
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Connect()", "Attempting to connect...");

        if (connect(socket_peer, peer_address->ai_addr, peer_address->ai_addrlen)) {
            std::stringstream connectSS; connectSS << "connect() failed errno:(" << GETSOCKETERRNO() << ")";
            throw (connectSS.str());
        }
        
        // Setup encryption keys
        unsigned char publicKey[DH_PUBLICKEY_SIZE_BYTES];
        if (!upEncryptionHandle->GetDHPubKey(publicKey))
            throw ("GetDHPubKey failed.");

        if (!this->m_Send(MessageType::SECURECON, publicKey, DH_PUBLICKEY_SIZE_BYTES, false))
            throw ("m_Send failed.");

        // Recieve the peer public key
        Packet recievedPacket;
        do{
            if (!this->m_Recv(socket_peer, recievedPacket, false))
                throw ("m_Recv failed.");
        
        } while (recievedPacket.GetMsgType() != MessageType::SECURECON);
    
        // Set our public peer key then derive secret key
        if (!upEncryptionHandle->SetDHPublicPeer(*recievedPacket.GetBytes(), recievedPacket.GetBytesSize()))
            throw ("SetDHPublicPeer failed.");
        if (!upEncryptionHandle->DeriveSecretKey())
            throw ("DeriveSecretKey failed.");

        freeaddrinfo(peer_address);
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Connect()", "Connected.");
        NetworkHandler::s_SetConnectedFlag(true);

        // Set socket into non-blocking mode
        // We enable it after the connect call as we do not want 
        u_long iMode = 1;
        if (ioctlsocket(socket_peer, FIONBIO, &iMode) != NO_ERROR)
            throw ("Error setting socket as non-blocking");

        return true;
    }
    catch(const char* err)
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Connect", "Error: ", err);
        return false;
    }
}


bool NetworkHandler::m_ReceiveMessage(std::string& messageOut, MessageHandler* p_messageHandler)
{
    WSAPOLLFD fds[1];
    fds[0].fd = socket_peer;
    fds[0].events = POLLRDNORM;  

    constexpr int POLL_TIMEOUT_MS = 1;

    try
    {
        int retCode = WSAPoll(fds, 1, POLL_TIMEOUT_MS);
        if (retCode == SOCKET_ERROR)
            throw ("Error occured WSAPoll().");

        else if (retCode != 0)
        {
            Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_ReceiveMessage()", "Packet available");

            Packet networkPacket;
            if (!m_Recv(socket_peer, networkPacket))
            {
                NetworkHandler::s_SetConnectedFlag(false);
                throw ("Error occured in m_Recv()");
            }
            Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_ReceiveMessage()", 
                                             "Packet type (", MessageType::GetMessageType(networkPacket.GetMsgType()), ") : ", networkPacket.GetString());
            
            // We now handle the message accordingly
            switch (networkPacket.GetMsgType())
            {
                // Print out message
                case MessageType::ALIASACK:
                {
                    p_messageHandler->s_SetUserAlias(networkPacket.GetString());
                    MessageHandler::m_aliasSet = true;
                    messageOut = "You've joined the chat room.";
                    return true;
                }
                case MessageType::ALIASSET:
                case MessageType::ALIASDNY:
                case MessageType::MESSAGE:
                {
                    messageOut = networkPacket.GetString();
                    return true;
                }
                case MessageType::CONNUSERS:
                {
                    try{
                        NetworkHandler::m_knownConnectedUsers = std::stoi(networkPacket.GetString());
                    }
                    catch (const std::invalid_argument& e)
                    {
                        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_ReceiveMessage()", 
                                                         "Error: Invalid number of connected users: ", networkPacket.GetString());
                        return false;
                    }

                    Display::s_DrawInfoDisplayMux(p_messageHandler);
                    return false;
                }
                case MessageType::SECURECON:
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
    catch(const char* err)
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_ReceiveMessage", "Error: ", err);
        return false;
    }
}


bool NetworkHandler::m_Send(const unsigned char msgType, const unsigned char* data, const size_t dataSize, bool encrypted)
{
    constexpr int PAYLOADBUFFERSIZE = 2;
    try
    {
        if (encrypted)
        {
            // Setup encryption hashes, IVs and payload
            unsigned char IV[AESIV_SIZE_BYTES];
            if (!upEncryptionHandle->s_GenerateIV(IV))
                throw ("Generate IV failed.");

            std::unique_ptr<unsigned char[]> encryptedPayload;
            int encryptedPayloadSize = upEncryptionHandle->EncryptData(*data, dataSize, *IV, encryptedPayload);
            if (encryptedPayloadSize == -1)
                throw ("EncryptData failed.");
            
            // Create buffer for IV and enc payload to generate signature for
            std::unique_ptr<unsigned char[]> packetIVPayload = std::make_unique<unsigned char[]>(AESIV_SIZE_BYTES + encryptedPayloadSize);
            std::memcpy(packetIVPayload.get(), IV, 16);
            std::memcpy(packetIVPayload.get() + 16, encryptedPayload.get(), encryptedPayloadSize);

            unsigned char signature[SHA256_AES_ENCRYPTED_BYTES];
            if(!upEncryptionHandle->CreatePacketSig(*packetIVPayload.get(), AESIV_SIZE_BYTES + encryptedPayloadSize, *IV, signature))
                throw ("Create packet signature failed.");

            // 1 is the message type
            std::uint16_t payloadSize = 1 + SHA256_AES_ENCRYPTED_BYTES + AESIV_SIZE_BYTES + encryptedPayloadSize;
            // Turn the 16 bit integer into two bytes 0-65535
            std::uint8_t payloadSizeBytes[PAYLOADBUFFERSIZE] = {static_cast<std::uint8_t>(payloadSize >> 8), 
                                                                static_cast<std::uint8_t>(payloadSize & 0xFF)};
            
            // +2 for size bytes
            std::unique_ptr<unsigned char[]> dataToSend = std::make_unique<unsigned char[]>(payloadSize+PAYLOADBUFFERSIZE);
            std::memcpy(dataToSend.get(), payloadSizeBytes, PAYLOADBUFFERSIZE);                             // Size data
            std::memcpy(dataToSend.get()+PAYLOADBUFFERSIZE, &msgType, 1);                                   // Message type data
            std::memcpy(dataToSend.get()+TYPEANDSIZEBYTES, signature, SHA256_AES_ENCRYPTED_BYTES);          // Encrypted Signature
            std::memcpy(dataToSend.get()+TYPEANDSIZEBYTES+SHA256_AES_ENCRYPTED_BYTES, 
                        packetIVPayload.get(), AESIV_SIZE_BYTES + encryptedPayloadSize);    // Encrypted Signature

            return send(socket_peer, reinterpret_cast<const char*>(dataToSend.get()), payloadSize+PAYLOADBUFFERSIZE, 0);
        }
        else
        {
            // 1 is the message type. Payload is the packet without the size bytes.
            std::uint16_t payloadSize = 1 + dataSize;
            // Turn the 16 bit integer into two bytes 0-65535
            std::uint8_t payloadSizeBytes[PAYLOADBUFFERSIZE] = {static_cast<std::uint8_t>(payloadSize >> 8), 
                                                                static_cast<std::uint8_t>(payloadSize & 0xFF)};
            // Assemble packet
            std::unique_ptr<unsigned char[]> dataToSend = std::make_unique<unsigned char[]>(dataSize+TYPEANDSIZEBYTES);
            std::memcpy(dataToSend.get(), payloadSizeBytes, PAYLOADBUFFERSIZE);     // Size of the payload
            std::memcpy(dataToSend.get()+PAYLOADBUFFERSIZE, &msgType, 1);           // Message type
            std::memcpy(dataToSend.get()+TYPEANDSIZEBYTES, data, dataSize);         // Data

            return send(socket_peer, reinterpret_cast<const char*>(dataToSend.get()), payloadSize+PAYLOADBUFFERSIZE, 0);
        }
    }
    catch(const char* err)
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Send", "Error: ", err);
        return false;
    }
}


bool NetworkHandler::m_Recv(SOCKET connection, Packet &incomingPacketOut, bool encrypted)
{
    std::uint8_t packetSizeBuffer[2];
    std::unique_ptr<std::uint8_t[]> packetBuffer;

    try
    {
        // Get packet size
        int recvLengthSize = recv(connection, reinterpret_cast<char*>(packetSizeBuffer), sizeof(packetSizeBuffer), 0);
        if (recvLengthSize == -1)
        {
            if (GETSOCKETERRNO() == WSAECONNRESET)
                throw ("Socket was forcefully reset by connected peer.");
        }
        else if (recvLengthSize == 0)
            throw ("recv length 0: connection dropped.");

        std::uint16_t packetSize;
        packetSize = (static_cast<std::uint16_t>(packetSizeBuffer[0]) << 8) + static_cast<std::uint16_t>(packetSizeBuffer[1]);
        
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Recv", "Packet size recieved: ", packetSize);
        
        // Once we have the message length we can get the packet
        packetBuffer = std::make_unique<std::uint8_t[]>(packetSize);
        int recvPacketSize = recv(connection, reinterpret_cast<char*>(packetBuffer.get()), packetSize, 0);

        // Check for errors
        if (recvPacketSize == -1)
        {
            if (GETSOCKETERRNO() == WSAECONNRESET)
                throw ("Socket was forcefully reset by connected peer.");
        }
        else if (recvLengthSize == 0)
            throw ("recv packet 0: connection dropped.");

        if (encrypted)
        {
            // Get IV offset
            unsigned char* SIG = packetBuffer.get() + SIGNATURE_OFFSET;
            unsigned char* IV = packetBuffer.get() + IV_OFFSET;
            unsigned char* payload = packetBuffer.get() + PAYLOAD_OFFSET;

            // We first have to verify the packet (IV+payload)
            if(!upEncryptionHandle->VerifyPacket(*SIG, *IV, *IV, packetSize-IV_OFFSET))
                throw ("Packet verification failed.");
            Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Recv", "Packet verified.");
            
            std::unique_ptr<unsigned char[]> decryptedPacketPayload;

            // Then we decrypt the payload and set the packet struct with its data
            int decryptedPayloadBytes;
            if (-1 == (decryptedPayloadBytes = upEncryptionHandle->DecryptData(*payload, packetSize-PAYLOAD_OFFSET, *IV, decryptedPacketPayload)))
                throw ("Data decryption failed.");

            Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Recv", "Successful decryption.");
            incomingPacketOut.SetBytes(decryptedPacketPayload.get(), decryptedPayloadBytes);
        }
        else
        {
            // Get all the data except the message type
            incomingPacketOut.SetBytes(packetBuffer.get()+1, packetSize-1);
        }

        // Same either encrypted or not
        incomingPacketOut.SetMessageType(packetBuffer[0]);
        return true;
    }
    catch (const char* err)
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Recv", "Error: ", err);
        return false;
    }
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

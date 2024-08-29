#include "networkHandler.hpp"
#include "../logging.hpp"
#include "../messageHandler.hpp"

#include <sstream>

// Static declares
bool NetworkHandler::bConnectedFlag = false;
std::mutex NetworkHandler::connectedFlagMutex;


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


bool NetworkHandler::m_RecieveMessage(std::string& messageOut)
{
    WSAPOLLFD fds[1];
    fds[0].fd = socket_peer;
    fds[0].events = POLLRDNORM;  

    int retCode = WSAPoll(fds, 1, 1);
    if (retCode == SOCKET_ERROR)
    {
        std::stringstream recvSS; recvSS << "Error occured WSAPoll(): " << errno;
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessages()", recvSS.str());
    }

    else if (retCode != 0)
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessage()", "Packet available");
        
        int readBufferSize = 4;
        char* readBuffer = (char*)calloc(readBufferSize, sizeof(char));
        int bytesRecived = 0;
        int totalBytes = 0;

        do {
            // Our buffer is maxed, we need to extend it
            if (totalBytes >= readBufferSize)
            {
                Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessage()", 
                    "Buffer maxed, doubling: ", readBufferSize, " bytes -> ", readBufferSize*2, " bytes");

                // Fails
                readBuffer = (char*)realloc(readBuffer, (readBufferSize * 2));
                // Zero out our new memory
                memset(readBuffer + readBufferSize, '\0', readBufferSize);
                readBufferSize*=2; 
            }

            // Recieve the data from the socket
            bytesRecived = recv(socket_peer, readBuffer+totalBytes, readBufferSize/2, 0);
            
            // -1 = finished async recv
            if (bytesRecived == -1)
            {
                // Acknowledge error
                GETSOCKETERRNO();
                break;
            }
            
            else if (bytesRecived == 0)
                break;

            totalBytes += bytesRecived;
        } while (true);

        // Pass the memory to a string type (RAII)
        std::string readBufferString(readBuffer, totalBytes);
        free(readBuffer);
        
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessage()", "Total bytes recieved: ", totalBytes);

        // No bytes recieved then we treat as disconnect
        if (totalBytes == 0)
        {
            // TODO disconnect
            // this->m_DisconnectUser(connectedUser);
            return false;
        }

        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessage()", "Message: ", readBufferString);

        // We now handle the message accordingly
        // Check first byte
        unsigned char msgType = readBufferString[0];
        switch (msgType)
        {
            // Print out message
            case MessageType::ALIASACK:
            {
                // TODO update alias info heading
                MessageHandler::m_aliasSet = true;
                messageOut = "You've joined the chat room.";
                return true;
            }

            case MessageType::ALIASSET:
            case MessageType::ALIASDNY:
            case MessageType::MESSAGE:
            {
                messageOut = readBufferString.substr(1, readBufferString.size()-1);
                return true;
            }

            case MessageType::CONNUSERS:
            {
                // TODO Update connusers info heading
                return false;
            }
            default:
            {
                Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessage()", "Invalid packet type: ", MessageType::GetMessageType(msgType), "(", (int)msgType, ")");
                break;
            }
        }
        // false
    }
    return false;
}


bool NetworkHandler::m_Send(unsigned char msgType, const std::string& msg)
{
    std::string message = static_cast<char>(msgType) + msg;
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Send()", "Send: '", msg, "' (", msg.size(), " bytes)");
    return send(socket_peer, message.c_str(), message.size(), 0);
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

#include "networkHandler.hpp"
#include "../logging.hpp"

#include <sstream>

// Static declares
bool NetworkHandler::bConnectedFlag = false;
std::mutex NetworkHandler::connectedFlagMutex;


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
        return false;
    }
    // // Set socket into non-blocking mode
    // u_long iMode = 1;
    // if (ioctlsocket(socket_peer, FIONBIO, &iMode) != NO_ERROR)
    //     Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", "Error setting socket as non-blocking");

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
    return true;
}


std::string NetworkHandler::m_RecieveMessages(void)
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
    // We have a packet to process
    else if (retCode != 0)
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessages()", "Packet available");
        
        int readBufferSize = 512;
        char* readBuffer = (char*)calloc(readBufferSize, sizeof(char));
        int bytesRecived = 0;

        // int retCode2;
        // do {
        //     // Resize the read in buffer
        //     if (bytesRecived >= readBufferSize){
        //         // Double input buffer size
        //         Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessages()", "Double");

        //         readBuffer = (char*)realloc(readBuffer, readBufferSize *= 2);
        //     }
        //     bytesRecived = recv(socket_peer, readBuffer, readBufferSize, 0);
        //     Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessages()", "Marker");
        //     retCode2 = WSAPoll(fds, 1, 1);
        // } while (retCode2 != 0);

        bytesRecived = recv(socket_peer, readBuffer, readBufferSize, 0);

        std::string bytesRecvMsg = "Bytes recieved: ";
        bytesRecvMsg += std::to_string(bytesRecived);
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessages()", bytesRecvMsg);

        std::string msg = readBuffer;
        free(readBuffer);

        return msg;            
    }
    // Nothing
    return "";
}


bool NetworkHandler::m_Send(std::string msg)
{
    std::stringstream ss; ss << "Sent: '" << msg << "' (" << msg.size() << " bytes)";
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Send()", ss.str());
    return send(socket_peer, msg.c_str(), msg.size(), 0);
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

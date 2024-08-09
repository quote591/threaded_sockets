#include "networkHandler.hpp"
#include "../logging.hpp"

#include <sstream>

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

    std::stringstream getNameInfoSS; getNameInfoSS << "Remote address: " << address_buffer << ":" << service_buffer << ")";
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
    return true;
}


bool NetworkHandler::m_Connect()
{
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Connect()", "Creating socket...");

    // Connect
    
    if (connect(socket_peer,
        peer_address->ai_addr, peer_address->ai_addrlen)) {
        
        std::stringstream connectSS; connectSS << "connect() failed errno:(" << GETSOCKETERRNO() << ")";
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Connect()", connectSS.str());
        return false;
    }
    freeaddrinfo(peer_address);
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Connect()", "Connected.");
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
        int read_buffer_size = 256;
        char* read_buffer = (char*)calloc(read_buffer_size, sizeof(char));
        int bytes_recived = 0;

        recv(socket_peer, read_buffer, read_buffer_size, 0);

        do {
            // Resize the read in buffer
            if (bytes_recived >= read_buffer_size){
                // Double input buffer size
                read_buffer = (char*)realloc(read_buffer, read_buffer_size *= 2);
            }
        // Keep reading while there is data
        } while ((bytes_recived = recv(socket_peer, read_buffer, read_buffer_size, 0)) > 0);

        std::string msg = read_buffer;
        free(read_buffer);

        return msg;            
    }
    // Nothing
    return "";
}

bool NetworkHandler::m_Send(std::string msg)
{
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
    return true;
}

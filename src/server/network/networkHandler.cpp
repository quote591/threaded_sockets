#include "networkHandler.hpp"
#include "../logging.hpp"

#include <sstream>
#include <thread>
#include <future> // async
#include <memory>


void NetworkHandler::m_AsyncNewConnectionHandle(SOCKET userSocket, const char address[NI_MAXHOST])
{
    SetSocketBlocking(true, userSocket);

    // Get alias packet
    char aliasBuffer[128];
    std::memset(aliasBuffer, 0, sizeof(aliasBuffer));

    // Alias packet
    // alias:username\0
    int recvSize = recv(userSocket, aliasBuffer, sizeof(aliasBuffer)-1, 0);

    // TODO, if the username is not right, send the connected user info on what
    if (std::strncmp(aliasBuffer, "alias:", 6) || recvSize < 7 || recvSize > 16)
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_AsyncNewConnectionHandle", 
            "Alias packet was not matching failed connection, return. Packet recv: ", aliasBuffer);
        // Failed TODO disconnect user
        return;
    }
    char alias[11];
    std::strcpy(alias, aliasBuffer+6);

    Log::s_GetInstance()->m_LogWrite("NetworkHanlder::m_AsyncNewConnectionHandle",
        "New user connected: ", alias, " from ", address);

    std::shared_ptr<NetworkedUser> userStruct = std::make_shared<NetworkedUser>(
        userSocket, alias, time(NULL), address
    );

    m_AddNetworkedUser(userStruct);

    SetSocketBlocking(false, userSocket);
}


void NetworkHandler::m_AddNetworkedUser(spNetworkedUser user)
{
    std::lock_guard<std::mutex> lock(connectedUserVectorMutex);
    connectedUsers.push_back(user);

}


std::vector<spNetworkedUser> NetworkHandler::m_GetNetworkedUsers(void)
{
    std::lock_guard<std::mutex> lock(connectedUserVectorMutex);
    return connectedUsers; // Copy return
}


int NetworkHandler::m_GetNetworkedUsersCount(void)
{
    std::lock_guard<std::mutex> lock(connectedUserVectorMutex);
    return connectedUsers.size();
}


void NetworkHandler::SetSocketBlocking(bool blocking, SOCKET socket)
{
    u_long iMode = (blocking) ? 1 : 0;

    const char* ioctlsocketMsg;
    if (ioctlsocket(m_serverSocket, FIONBIO, &iMode) != NO_ERROR)
        if (blocking)
            ioctlsocketMsg = "Error setting socket as blocking ";
        else
            ioctlsocketMsg = "Error setting socket as non-blocking ";
    else
    {
        if (blocking)
            ioctlsocketMsg = "Set socket into blocking mode ";
        else
            ioctlsocketMsg = "Set socket into non-blocking mode ";
    }
    
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::SetSocketBlocking()", ioctlsocketMsg, static_cast<int>(socket));
}


bool NetworkHandler::m_Create(std::string port)
{
    // Set version for winsock2
    #if defined(_WIN32)
	WSADATA d;
	if (WSAStartup(MAKEWORD(2, 2), &d)) {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", "Failed to initalize ", errno);
		return false;
	}
    #endif
    
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", "Configuring local address...");
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6; // ipv6
	hints.ai_socktype = SOCK_STREAM; // tcp
	hints.ai_flags = AI_PASSIVE; // Tells getaddrinfo() to bind to the wildcard address

	struct addrinfo* bindAddress;
	/* getaddrinfo here generates an address for bind() */
	if (getaddrinfo(0, port.c_str(), &hints, &bindAddress)){
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", "mServerTCPCreate error. getaddrinfo() failed. (", GETSOCKETERRNO(), ")");
		return false;
	}
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", "Creating socket...");

	m_serverSocket = socket(bindAddress->ai_family,
	                      bindAddress->ai_socktype, bindAddress->ai_protocol);

	/* check if the call to socket() was sucessful */
	if (!ISVALIDSOCKET(m_serverSocket)) {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", "socket() failed. (", GETSOCKETERRNO(), ")");
		return false;
	}

    int optCode = 0;
    // Turn off ipv6 only option on the ipv6 level of the socket
    if (setsockopt(m_serverSocket, IPPROTO_IPV6, IPV6_V6ONLY,
                   (char*)&optCode, sizeof(int)))
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", "setsockopt() failed. (", GETSOCKETERRNO(), ")");
        return false;
	}

    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", "Binding socket to local address...");

	// bind returns 0 on success
	if (bind(m_serverSocket, bindAddress->ai_addr, bindAddress->ai_addrlen)) {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", "bind() failed. (", GETSOCKETERRNO(), ")");

        // In the case where bind fails the resorses are still freed
		freeaddrinfo(bindAddress); 
		return false;
	}



	// release address memory
	freeaddrinfo(bindAddress);
	return true;
}


bool NetworkHandler::m_Listen(int connections)
{
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Listen()", "Started listening...");

	// Listen returns 0 upon success
	if (listen(m_serverSocket, connections) < 0) {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", "listen() failed. (", GETSOCKETERRNO(), ")");
		return false;
	}
    return true;
}

bool NetworkHandler::m_Accept()
{
    WSAPOLLFD fds[1];

    fds[0].fd = m_serverSocket;
    fds[0].events = POLLRDNORM;

    // Sockets, number of sockets, timeout (ms)
    int retCode = WSAPoll(fds, 1, 1);
    if (retCode == SOCKET_ERROR)
    {
        printf("Error occured, errno: %d", errno);
        return false;
    }
    else if (retCode == 0)
    {
        // printf("Nothing yet.");
        return false; // Non-blocking socket says there is nothing (no error)
    }
    else
    {
        printf("Ready to accept");
    }

    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Accept()", "Started accepting...");
	/* we have to store the clients connection info */
	/* the type will guarentee the type is large enough to hold this data */
	struct sockaddr_storage client_address;
	/* client len will differ depending on Ipv4/6*/
	socklen_t client_len = sizeof(client_address);
	/* now a tcp connection has been astablished */
    /* potentially blocking*/
	SOCKET socketClient = accept(m_serverSocket,
		(struct sockaddr*) &client_address, &client_len);

	if (!ISVALIDSOCKET(socketClient)) {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Accept()", "accept() failed. (", GETSOCKETERRNO(), ")");
		return false;
	}

	/* connection esablished, info */
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Accept()", "Client is connected...");
	char address_buffer[NI_MAXHOST]; // NI_MAXHOSTS (<netdb.h>)

	/* client address, client address length (for ipv4 or 6), output buffer, and length, hostname output(leave so null), "", Flag specifies we dont want to see hostname of ip addresses */
	getnameinfo((struct sockaddr*)&client_address,
		client_len, address_buffer, sizeof(address_buffer), 0, 0,
		NI_NUMERICHOST);
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Accept()", "Client is connected...");

    // We know the connection is successful, now we hand off to the async thread to deal with our new connection
    
    // Future must be kept otherwise the async will not complete
    // Might have to add to acception vector in the NetworkHandler since we will fall out of scope after this is launched 
    auto result = std::async(std::launch::async, m_AsyncNewConnectionHandle, this, socketClient, address_buffer);

	printf("%s\n", address_buffer);

    return true;
}



std::string NetworkHandler::m_RecieveMessage(spNetworkedUser connectedUser)
{
    NetworkedUser* test;
    WSAPOLLFD fds[1];
    fds[0].fd = connectedUser->GetUserSocket();
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
        
        int readBufferSize = 4;
        char* readBuffer = (char*)calloc(readBufferSize, sizeof(char));
        int bytesRecived = 0;
        int totalBytes = 0;

        do {
            // Our buffer is maxed, we need to extend it
            if (totalBytes >= readBufferSize)
            {
                std::stringstream ss; ss << "Buffer maxed, doubling size (" << readBufferSize << "bytes -> " << readBufferSize*2 << "bytes)";
                Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessages()", ss.str());

                // Fails
                readBuffer = (char*)realloc(readBuffer, (readBufferSize * 2));
                // Zero out our new memory
                memset(readBuffer + readBufferSize, '\0', readBufferSize);
                // Extend buffer var
                readBufferSize*=2; 
            }

            // Recieve the data from the socket
            // bytesRecived = recv(socket_peer, readBuffer+totalBytes, readBufferSize/2, 0);
            
            // Non-blocking sockets throw an error when they have no data to provice. 
            if (bytesRecived == -1)
            {
                // Acknowledge error and return
                GETSOCKETERRNO();
                Log::s_GetInstance()->m_LogWrite("NetworkHandle::m_RecieveMessages()", "Finished message. Return");
                break;
            }
            totalBytes += bytesRecived;
        } while (true);
        
        // If we recieve a message and get 0 bytes. The socket connection is closed.
        if (totalBytes == 0)
        {
            // NetworkHandler::s_SetConnectedFlag(false);
            return "";
        }


        std::string bytesRecvMsg = "Bytes recieved: ";
        bytesRecvMsg += std::to_string(totalBytes);
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessages()", bytesRecvMsg);

        std::string msg = readBuffer;
        free(readBuffer);

        return msg;            
    }
    // Nothing
    return "";

    return std::string();
}


bool NetworkHandler::m_BroadcastMessage(std::string message)
{
    return false;
}


bool NetworkHandler::m_Send(spNetworkedUser connectedUser, std::string message)
{
    return false;
}


bool NetworkHandler::m_Shutdown(void)
{
    return false;
}

















// bool NetworkHandler::m_Create(std::string hostName, std::string port)
// {
//     // Not filled in 
//     if (hostName.c_str() == NULL || port.c_str() == NULL){
//         return false;
//     }

//     // Set windows socket version
// #ifdef _WIN32
//     WSADATA d;
//     if (WSAStartup(MAKEWORD(2, 2), &d)) {
//         Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", "error: WSAStartup() failed to initalize.");
//         return false;
//     }
// #endif

//     struct addrinfo hints;
//     memset(&hints, 0, sizeof(hints));
//     // TCP UDP(SOCK_DGRAM)
//     hints.ai_socktype = SOCK_STREAM;
//     // struct addrinfo* peer_address;
//     if (getaddrinfo(hostName.c_str(), port.c_str(), &hints, &peer_address)) {
//         std::stringstream getAddrInfoSS; getAddrInfoSS << "error: getaddrinfo() failed. Errno " << GETSOCKETERRNO() << ")";
//         Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", getAddrInfoSS.str());
//         return false;
//     }

//     // Again variable arrays potentially
//     char address_buffer[100];
//     char service_buffer[100];
//     getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen,
//         address_buffer, sizeof(address_buffer),
//         service_buffer, sizeof(service_buffer),
//         NI_NUMERICHOST);

//     std::stringstream getNameInfoSS; getNameInfoSS << "Remote address: " << address_buffer << ":" << service_buffer;
//     Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", getNameInfoSS.str());

//     // Create socket
//     Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", "Creating socket...");

//     socket_peer = socket(peer_address->ai_family,
//         peer_address->ai_socktype, peer_address->ai_protocol);
//     if (!ISVALIDSOCKET(socket_peer)) {
//         std::stringstream isValidSocketSS; isValidSocketSS << "error: socket() failed. errno: (" << GETSOCKETERRNO() << ")";
//         Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", isValidSocketSS.str());
//         return false;
//     }
//     // // Set socket into non-blocking mode
//     // u_long iMode = 1;
//     // if (ioctlsocket(socket_peer, FIONBIO, &iMode) != NO_ERROR)
//     //     Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", "Error setting socket as non-blocking");

//     return true;
// }


// bool NetworkHandler::m_Connect()
// {
//     Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Connect()", "Attempting to connect...");

//     // Connect
    
//     if (connect(socket_peer,
//         peer_address->ai_addr, peer_address->ai_addrlen)) {
        
//         std::stringstream connectSS; connectSS << "connect() failed errno:(" << GETSOCKETERRNO() << ")";
//         Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Connect()", connectSS.str());
//         return false;
//     }
//     freeaddrinfo(peer_address);
//     Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Connect()", "Connected.");
//     return true;
// }

// std::string NetworkHandler::m_RecieveMessages(void)
// {
//     WSAPOLLFD fds[1];
//     fds[0].fd = socket_peer;
//     fds[0].events = POLLRDNORM;  

//     int retCode = WSAPoll(fds, 1, 1);
//     if (retCode == SOCKET_ERROR)
//     {
//         std::stringstream recvSS; recvSS << "Error occured WSAPoll(): " << errno;
//         Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessages()", recvSS.str());
//     }
//     // We have a packet to process
//     else if (retCode != 0)
//     {
//         Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessages()", "Packet available");
        
//         int readBufferSize = 512;
//         char* readBuffer = (char*)calloc(readBufferSize, sizeof(char));
//         int bytesRecived = 0;

//         // int retCode2;
//         // do {
//         //     // Resize the read in buffer
//         //     if (bytesRecived >= readBufferSize){
//         //         // Double input buffer size
//         //         Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessages()", "Double");

//         //         readBuffer = (char*)realloc(readBuffer, readBufferSize *= 2);
//         //     }
//         //     bytesRecived = recv(socket_peer, readBuffer, readBufferSize, 0);
//         //     Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessages()", "Marker");
//         //     retCode2 = WSAPoll(fds, 1, 1);
//         // } while (retCode2 != 0);

//         bytesRecived = recv(socket_peer, readBuffer, readBufferSize, 0);

//         std::string bytesRecvMsg = "Bytes recieved: ";
//         bytesRecvMsg += std::to_string(bytesRecived);
//         Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessages()", bytesRecvMsg);

//         std::string msg = readBuffer;
//         free(readBuffer);

//         return msg;            
//     }
//     // Nothing
//     return "";
// }

// bool NetworkHandler::m_Send(std::string msg)
// {
//     std::stringstream ss; ss << "Sent: '" << msg << "' (" << msg.size() << " bytes)";
//     Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Send()", ss.str());
//     return send(socket_peer, msg.c_str(), msg.size(), 0);
// }


// bool NetworkHandler::m_Close(void)
// {
//     Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Close()", "Closing socket.");
//     CLOSESOCKET(socket_peer);

// #ifdef _WIN32
// WSACleanup();
// #endif
//     Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Close()", "Socket closed.");
//     return true;
// }

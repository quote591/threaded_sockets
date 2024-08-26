#include "networkHandler.hpp"
#include "../logging.hpp"

#include <sstream>
#include <thread>
#include <memory>
#include <iomanip>
#include <algorithm>

#define UNAME_MIN_SIZE 3
#define UNAME_MAX_SIZE 8

constexpr const char* namePrefix = "alias:";
constexpr size_t namePrefixSize = std::char_traits<char>::length(namePrefix); // complie time compute

void NetworkHandler::m_AsyncNewConnectionHandle(SOCKET userSocket, const char address[NI_MAXHOST])
{
    this->m_Send(userSocket, "Welcome, please submit a username. Like so - alias:name");

    SetSocketBlocking(true, userSocket);
    // Get alias packet
    char aliasBuffer[namePrefixSize+UNAME_MAX_SIZE];
    std::memset(aliasBuffer, 0, sizeof(aliasBuffer));

    // Alias packet
    // alias:username\0
    std::shared_ptr<NetworkedUser> userStruct;

    while (true)
    {    
        Log::s_GetInstance()->m_LogWrite("Async", "Socket: ", static_cast<int>(userSocket));
        int recvSize = recv(userSocket, aliasBuffer, sizeof(aliasBuffer)-1, 0);
        if (recvSize == -1)
        {
            Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_AsyncNewConnectionHandle()", "recv error WSAGetLastError(): ", GETSOCKETERRNO());
            return;
        }
        if (recvSize == 0)
        {
            // Connection dropped
            Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_AsyncNewConnectionHandle()", "connection dropped");
            return;
        }
        Log::s_GetInstance()->m_LogWrite("asnyc conncetion", "Packet size: ", recvSize, " ");

        // Username has to between 3 and 8 characters, if its not we will 
        if (std::strncmp(aliasBuffer, namePrefix, namePrefixSize) || 
            recvSize < static_cast<int>(namePrefixSize + UNAME_MIN_SIZE) || 
            recvSize > static_cast<int>(namePrefixSize + UNAME_MAX_SIZE))
        {
            this->m_Send(userSocket, "Username not acceptable - needs to be 3 to 8 chars long.");
        }
        // Username is fine
        else
        {
            char alias[11];
            std::strcpy(alias, aliasBuffer+namePrefixSize);

            userStruct = std::make_shared<NetworkedUser>(
                userSocket, alias, time(NULL), address
            );

            // Attempt to add the username, check for uniqueness
            if (m_AttemptAddNetworkedUser(userStruct))
                break;
            else
                this->m_Send(userSocket, "Username not acceptable - needs to be unique.");
        }
        std::memset(aliasBuffer, 0, sizeof(aliasBuffer)); // If username was not accepted, we null the memory again
    }
    SetSocketBlocking(false, userSocket);

    std::stringstream ssConnectionMsg;
    ssConnectionMsg << userStruct->m_GetUserAlias() << " connected.";
    m_BroadcastMessage(nullptr, ssConnectionMsg.str());
}


bool NetworkHandler::m_AttemptAddNetworkedUser(spNetworkedUser userIn)
{
    std::lock_guard<std::mutex> lock(connectedUserVectorMutex);

    auto it = std::find_if(std::begin(connectedUsers), std::end(connectedUsers), [&userIn](const spNetworkedUser& username)
    {
        return username->m_GetUserAlias() == userIn->m_GetUserAlias();
    });
    // Found
    if (it != std::end(connectedUsers))
    {
        return false;
    }

    connectedUsers.push_back(userIn);
    return true;
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


void NetworkHandler::m_ClearNetworkedUserVector(void)
{
    std::lock_guard<std::mutex> lock(connectedUserVectorMutex);
    connectedUsers.clear();
}


void NetworkHandler::m_AddAsyncConnectionJob(std::future<void>&& job)
{
    std::lock_guard<std::mutex> lock(asyncConnectionJobsMutex);

    // If we hit a certain amount of asyncconnection jobs, we have to remove some
    if (asyncConnectionJobs.size() > 3)
    {
        for (auto it = std::begin(asyncConnectionJobs); it != std::end(asyncConnectionJobs);)
        {
            if (it->wait_for(std::chrono::seconds(0)) == std::future_status::ready)
            {
                it = asyncConnectionJobs.erase(it);
            }
            else
                it++;
        }
    }
    // Add connection job
    asyncConnectionJobs.push_back(std::forward<std::future<void>>(job));
}

void NetworkHandler::SetSocketBlocking(bool blocking, SOCKET socket)
{
    u_long iMode = (blocking) ? 0 : 1;

    const char* ioctlsocketMsg;
    if (ioctlsocket(socket, FIONBIO, &iMode) != NO_ERROR)
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

    // Set the server socket as non-blocking
    this->SetSocketBlocking(false, m_serverSocket);

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
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Accept()", "WSAPoll() Error: ", GETSOCKETERRNO());
        return false;
    }
    else if (retCode == 0)
        return false; // Non-blocking socket says there is nothing (no error)


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
	char address_buffer[NI_MAXHOST]; // NI_MAXHOSTS (<netdb.h>)

	/* client address, client address length (for ipv4 or 6), output buffer, and length, hostname output(leave so null), "", Flag specifies we dont want to see hostname of ip addresses */
	getnameinfo((struct sockaddr*)&client_address,
		client_len, address_buffer, sizeof(address_buffer), 0, 0,
		NI_NUMERICHOST);
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Accept()", "Client is connected...");

    // We know the connection is successful, now we hand off to the async thread to deal with our new connection
    
    // Future must be kept otherwise the async will not complete
    // Might have to add to acception vector in the NetworkHandler since we will fall out of scope after this is launched 
    m_AddAsyncConnectionJob(std::async(std::launch::async, m_AsyncNewConnectionHandle, this, socketClient, address_buffer));

    return true;
}



bool NetworkHandler::m_RecieveMessage(spNetworkedUser connectedUser, std::string& messageOut)
{
    WSAPOLLFD fds[1];
    fds[0].fd = connectedUser->m_GetUserSocket();
    fds[0].events = POLLRDNORM;

    int retCode = WSAPoll(fds, 1, 1);
    if (retCode == SOCKET_ERROR)
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessage()", "Error occured WSAPoll(): ", GETSOCKETERRNO());
        return false;
    }
    // We have a packet to process
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
            bytesRecived = recv(connectedUser->m_GetUserSocket(), readBuffer+totalBytes, readBufferSize/2, 0);
            
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
        
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_RecieveMessage()", "Total bytes recieved: ", totalBytes);

        // No bytes recieved then we treat as disconnect
        if (totalBytes == 0)
        {
            this->m_DisconnectUser(connectedUser);
            return false;
        }

        // Message set
        messageOut = readBuffer;
        free(readBuffer);

        return true;
    }
    else
        return false;
}


bool NetworkHandler::m_BroadcastMessage(spNetworkedUser sender, std::string message)
{
    std::stringstream ssMessage;

    // Get current time
    auto now = std::chrono::system_clock::now();
    auto timer = std::chrono::system_clock::to_time_t(now);
    std::tm bt = *std::localtime(&timer); 
    ssMessage << std::put_time(&bt, "[%H:%M:%S] ");

    // Non-server message message
    if (sender != nullptr)
    {
        Log::s_GetInstance()->m_LogWrite("Broadcast", "Nullptr sender");
        // We put the user name in it
        ssMessage << sender->m_GetUserAlias() << ": ";
    }
    ssMessage << message;

    bool success = true;

    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_BroadcastMessage()",
                                     "Send message: ", ssMessage.str(), " to ", this->m_GetNetworkedUsersCount(), " users.");

    // For every connected socket, we send our message.
    for (auto& user : this->m_GetNetworkedUsers())
    {
        int bytesSent = send(user->m_GetUserSocket(), ssMessage.str().c_str(), ssMessage.str().size(), 0);
        // If fail
        if (bytesSent == -1)
        {
            success = false;
            Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_BroadcastMessage()", 
                "Message failed to send to ", user->m_GetUserAddress(), " - ", user->m_GetUserAlias(), " Message: ", ssMessage.str());
        }
    }
    return success;
}


bool NetworkHandler::m_Send(SOCKET recipient, std::string message)
{
    int bytesSent = send(recipient, message.c_str(), message.size(), 0);
    if (bytesSent == -1)
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Send()", "Send failed. Err: ", GETSOCKETERRNO());
        return false;
    }
    else
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Send()", "Sent ", bytesSent, " bytes");
    return true;
}

bool NetworkHandler::m_DisconnectUser(spNetworkedUser userToDisconnect)
{
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_DisconnectUser()", "Disconnecting user: ", userToDisconnect->m_GetUserAlias(), " at ", userToDisconnect->m_GetUserAddress());

    connectedUserVectorMutex.lock();
    auto it = std::find_if(std::begin(connectedUsers), std::end(connectedUsers), [&userToDisconnect](spNetworkedUser& user)
    {
        return user->m_GetUserSocket() == userToDisconnect->m_GetUserSocket();
    });

    // found, delete
    if (it != std::end(connectedUsers))
    {
        connectedUsers.erase(it);
        connectedUserVectorMutex.unlock();

        std::stringstream ssDisconnectMsg;
        ssDisconnectMsg << userToDisconnect->m_GetUserAlias() << " has disconnected.";
        m_BroadcastMessage(nullptr, ssDisconnectMsg.str());
        
        return true;
    }

    connectedUserVectorMutex.unlock();
    return false;
}

bool NetworkHandler::m_Shutdown(void)
{
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Shutdown()", "called, disconnecting ", this->m_GetNetworkedUsersCount(), " users.");
    for (auto& users : this->m_GetNetworkedUsers())
    {
        CLOSESOCKET(users->m_GetUserSocket());
    }
    this->m_ClearNetworkedUserVector();

#ifdef _WIN32
WSACleanup();
#endif
    return true;
}



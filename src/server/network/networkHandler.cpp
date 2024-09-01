#include "networkHandler.hpp"
#include "../logging.hpp"

#include <sstream>
#include <thread>
#include <memory>
#include <iomanip>
#include <algorithm>
#include <cassert>

#define UNAME_MIN_SIZE 3
#define UNAME_MAX_SIZE 8



std::string MessageType::GetMessageType(unsigned char msgByte)
{
    switch (msgByte)
    {
        case ALIASSET:  return "Alias set";
        case ALIASACK:  return "Alias acknowledge";
        case ALIASDNY:  return "Alias deny";
        case MESSAGE:   return "General message";
        case CONNUSERS: return "Connected users control";
        default:        return "Unknown";
    }
}

#include <iostream>

void NetworkHandler::m_AsyncNewConnectionHandle(SOCKET userSocket, const char address[NI_MAXHOST])
{
    this->m_Send(MessageType::ALIASSET, userSocket, "Welcome, please submit a username.");

    SetSocketBlocking(true, userSocket);

    std::shared_ptr<NetworkedUser> userStruct;

    Packet asyncAliasPacket;
    
    while (true)
    {
        try
        {
            if (!m_Recv(nullptr, &userSocket, asyncAliasPacket, true) || asyncAliasPacket.msgType != MessageType::ALIASSET)
            {
                Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_AsyncNewConnectionHandle()", "Recieve error.");
                return;
            }  
            
            if (asyncAliasPacket.message.size() < UNAME_MIN_SIZE || asyncAliasPacket.message.size() > UNAME_MAX_SIZE)
            {
                throw("Username not acceptable - needs to be 3 to 8 chars long.");
            }

            for (char& c : asyncAliasPacket.message)
            {
                if (!std::isprint(c) || c == ' ')
                    throw("Username has to contain printable characters.");
            }

            userStruct = std::make_shared<NetworkedUser>(
                userSocket, asyncAliasPacket.message, time(NULL), address
            );

            // Attempt to add the username, check for uniqueness
            if (!m_AttemptAddNetworkedUser(userStruct))
                throw("Username taken - needs to be unique.");


            // All passed
            break;
        }
        catch(const char* exceptionString)
        {
            Log::s_GetInstance()->m_LogWrite("Alias setting", "Exception: ", exceptionString);
            this->m_Send(MessageType::ALIASDNY, userSocket, exceptionString);
        }
    }
    SetSocketBlocking(false, userSocket);

    // Alias is accpeted, send an acknowledgement to the user and broadcast to all users
    m_Send(MessageType::ALIASACK, userSocket, asyncAliasPacket.message);

    std::stringstream ssConnectionMsg;
    ssConnectionMsg << userStruct->m_GetUserAlias() << " connected.";
    m_BroadcastMessage(MessageType::MESSAGE, nullptr, ssConnectionMsg.str());
    m_BroadcastMessage(MessageType::CONNUSERS, nullptr, std::to_string(m_GetNetworkedUsersCount()));
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
	if (WSAStartup(MAKEWORD(2, 2), &d))
    {
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
	if (getaddrinfo(0, port.c_str(), &hints, &bindAddress))
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", "mServerTCPCreate error. getaddrinfo() failed. (", GETSOCKETERRNO(), ")");
		return false;
	}
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Create()", "Creating socket...");

	m_serverSocket = socket(bindAddress->ai_family,
	                      bindAddress->ai_socktype, bindAddress->ai_protocol);

	/* check if the call to socket() was sucessful */
	if (!ISVALIDSOCKET(m_serverSocket))
    {
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
	if (bind(m_serverSocket, bindAddress->ai_addr, bindAddress->ai_addrlen))
    {
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


bool NetworkHandler::m_ReceiveMessage(spNetworkedUser connectedUser, std::string& messageOut)
{
    WSAPOLLFD fds[1];
    fds[0].fd = connectedUser->m_GetUserSocket();
    fds[0].events = POLLRDNORM;

    int retCode = WSAPoll(fds, 1, 1);
    if (retCode == SOCKET_ERROR)
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_ReceiveMessage()", "Error occured WSAPoll(): ", GETSOCKETERRNO());
        return false;
    }
    // We have a packet to process
    else if (retCode != 0)
    {
        Packet recievedPacket;

        // Returns true on success, errors on socket errors
        if (!m_Recv(connectedUser, nullptr, recievedPacket, false))
            return false;

        switch (recievedPacket.msgType)
        {
            // Regular message
            case MessageType::MESSAGE:
            {
                messageOut = recievedPacket.message;
                return true;
            }

            // Should not be recieving alias packets or connuserspackets
            case MessageType::ALIASSET:
            case MessageType::ALIASACK:
            case MessageType::ALIASDNY:
            case MessageType::CONNUSERS:
            default:
            {
                Log::s_GetInstance()->m_LogWrite("Invalid packet type: ", MessageType::GetMessageType(recievedPacket.msgType), "(", (int)recievedPacket.msgType, ")");
                break;
            }
        }
        // false
    }
    return false;
}


bool NetworkHandler::m_BroadcastMessage(unsigned char messageType, spNetworkedUser sender, std::string message)
{
    std::stringstream ssMessage;

    // Only add the time if the message is a general message
    if (messageType == MessageType::MESSAGE){
        // Get current time
        auto now = std::chrono::system_clock::now();
        auto timer = std::chrono::system_clock::to_time_t(now);
        std::tm bt = *std::localtime(&timer); 
        ssMessage << std::put_time(&bt, "[%H:%M:%S] ");

        // Non-server message message
        if (sender != nullptr)
        {
            // We put the user name in it
            ssMessage << sender->m_GetUserAlias() << ": ";
        }
    }

    ssMessage << message;

    bool success = true;

    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_BroadcastMessage()",
                                     "Send message: ", ssMessage.str(), " to ", this->m_GetNetworkedUsersCount(), " users.");

    // For every connected socket, we send our message.
    for (auto& user : this->m_GetNetworkedUsers())
    {
        if (!m_Send(messageType, user->m_GetUserSocket(), ssMessage.str()))
        {
            // If fail
            success = false;
            Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_BroadcastMessage()", 
                "Message failed to send to ", user->m_GetUserAddress(), " - ", user->m_GetUserAlias(), " Message: ", ssMessage.str());
        }
    }
    return success;
}


bool NetworkHandler::m_Send(unsigned char messageType, SOCKET recipient, const std::string& message)
{
    // Make sure our payload is not too big to fit in a TCP packet

    std::uint16_t payloadSize = 1 + message.size();
    assert(payloadSize < MAXTCPPAYLOAD);

    // Turn the integer into the two bytes to be written
    std::uint8_t payloadSizeBytes[2] = {static_cast<std::uint8_t>(payloadSize >> 8), static_cast<std::uint8_t>(payloadSize & 0xFF)};

    std::string fullMessage = std::string(reinterpret_cast<char*>(payloadSizeBytes), 2) + 
                              static_cast<char>(messageType) + message;

    int bytesSent = send(recipient, fullMessage.c_str(), fullMessage.size(), 0);
    if (bytesSent == -1)
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Send()", "Send failed. Err: ", GETSOCKETERRNO());
        return false;
    }
    else
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Send()", "Sent ", bytesSent, " bytes");
    return true;
}


bool NetworkHandler::m_Recv(spNetworkedUser senderStruct, SOCKET* senderSock, Packet& incomingPacketOut, bool blocking)
{
    // Incoming packet:
    // Bytes 0-1 (2bytes) message length
    // Byte 2 (1byte) message type
    // Byte 3-n (n bytes) message

    // Either senderStruct or senderSock are nullptr. We can only use one
    assert((senderStruct == nullptr) != (senderSock == nullptr));
    SOCKET socket = (senderStruct == nullptr) ? *senderSock : senderStruct->m_GetUserSocket();

    std::uint8_t packetSizeBuffer[2];

    // Get packet size
    int recvLengthSize = recv(socket, reinterpret_cast<char*>(packetSizeBuffer), sizeof(packetSizeBuffer), 0);

    // Deal with error based on blocking status 
    if (recvLengthSize == -1 && !blocking)
    {
        GETSOCKETERRNO();
    }
    else if (recvLengthSize == -1 && blocking)
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Recv()", "Length recv (", GETSOCKETERRNO(), ")");
        return false;
    }
    // No packet, connection dropped
    else if (recvLengthSize == 0)
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Recv()", "recv length 0: connection dropped.");

        // Drop the senderstruct. If regular socket we can just return
        if (senderStruct != nullptr) m_DisconnectUser(senderStruct);
        return false;
    }

    std::uint16_t packetSize;
    packetSize = (static_cast<std::uint16_t>(packetSizeBuffer[0]) << 8) + static_cast<std::uint16_t>(packetSizeBuffer[1]);
    
    // Once we have the message length we can get the packet
    std::uint8_t* packetBuffer = (std::uint8_t*)malloc(packetSize);

    int recvPacketSize = recv(socket, reinterpret_cast<char*>(packetBuffer), packetSize, 0);
    if (recvPacketSize == -1 && !blocking)
    {
        GETSOCKETERRNO();
    }
    else if (recvPacketSize == -1 && blocking)
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Recv()", "Packet recv (", GETSOCKETERRNO(), ")");
        free(packetBuffer);
        return false;
    }
    else if (recvLengthSize == 0)
    {
        Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_Recv()", "recv packet: connection dropped.");
        free(packetBuffer);

        // Drop the senderstruct. If regular socket we can just return
        if (senderStruct != nullptr) m_DisconnectUser(senderStruct);
        return false;
    }

    incomingPacketOut.msgType = packetBuffer[0];
    incomingPacketOut.message = std::string(reinterpret_cast<char*>(packetBuffer+1), recvPacketSize-1);

    free(packetBuffer);
    return true;
}


bool NetworkHandler::m_DisconnectUser(const spNetworkedUser userToDisconnect)
{
    Log::s_GetInstance()->m_LogWrite("NetworkHandler::m_DisconnectUser()", "Disconnecting user: ", userToDisconnect->m_GetUserAlias());

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
        m_BroadcastMessage(MessageType::MESSAGE, nullptr, ssDisconnectMsg.str());
        m_BroadcastMessage(MessageType::CONNUSERS, nullptr, std::to_string(m_GetNetworkedUsersCount()));
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

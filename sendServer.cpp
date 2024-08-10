#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

// Threading headers
#include <thread>
#include <mutex>

// other 
#include <iostream>

// #pragma comment(lib,"Ws2_32.lib")

#define GETSOCKETERRNO() (WSAGetLastError())
#define ISVALIDSOCKET(s) ((s) >= 0)

// SOCKET socket_peer;
// struct addrinfo* peer_address;

WSADATA d;
SOCKET socket_listen;
SOCKET socket_client;

bool create(std::string _port)
{
    // Set version for winsock2
    #if defined(_WIN32)
	// WSADATA d;
	if (WSAStartup(MAKEWORD(2, 2), &d)) {
        std::cerr << "Failed to initalize." << errno << std::endl;
		return false;
	}
    #endif

    // TODO ALTER TO C++
	printf("Configuring local address...\n");
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	/* AF_INET = ipv4 */
	hints.ai_family = AF_INET6;
	/* TCP, soCK_DGRAM = UDP */
	hints.ai_socktype = SOCK_STREAM;
	/* Tells getaddrinfo() to bind to the wildcard address */
	hints.ai_flags = AI_PASSIVE;

	struct addrinfo* bind_address;
	/* getaddrinfo here generates an address for bind() */
	/* to do this we pass null as first param */
	if (getaddrinfo(0, _port.c_str(), &hints, &bind_address)){
		std::cerr << "mServerTCPCreate error.\ngetaddrinfo() failed. (" << GETSOCKETERRNO() << ")" << std::endl;
		return false;
	}

	printf("Creating socket...\n");
	// SOCKET socket_listen;
	socket_listen = socket(bind_address->ai_family,
		bind_address->ai_socktype, bind_address->ai_protocol);

	/* check if the call to socket() was sucessful */
	if (!ISVALIDSOCKET(socket_listen)) {
        std::cerr << "socket() failed. (" << GETSOCKETERRNO() << ")" << std::endl;
		return false;
	}


	/* implementation of duel stack ipv4 and ipv6 */
	/* when an ipv4 connection connects the ipv4 is remapped to ipv6 */
	/* first 96 bits are 0:0:0:0:0:ffff and the last 32 bits are the ipv4 address */

	// WORKS
// if (retCode = setsockopt(socket_listen, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&retCode, sizeof(&retCode)))

	// optCode has to be used otherwise we throw an error, dont know why. Just do it
	int optCode = 0;
	if (setsockopt(socket_listen, IPPROTO_IPV6, IPV6_V6ONLY, 
				reinterpret_cast<char *>(&optCode), sizeof(optCode)))
    {
        std::cerr << "setsockopt() failed. (" << GETSOCKETERRNO() << ")" << std::endl;

	}

	/* Bindt socket to local address */
	/* bind returns 0 on success*/
	printf("Binding socket to local address...\n");
	if (bind(socket_listen,
			bind_address->ai_addr, bind_address->ai_addrlen)) {
        std::cerr << "bind() failed. (" << GETSOCKETERRNO() << ")" << std::endl;
		freeaddrinfo(bind_address); // In the case where bind fails the resorses are still freed
		return false;
	}
	/* release address memory */
	freeaddrinfo(bind_address);
	return true;
}

bool listen(int connections)
{
    printf("listen() start");


    /* Start listening */
    std::cout << "Listening called..." << std::endl;
	/* 10 connections are allowed to queue up */
	if (listen(socket_listen, connections) < 0) {
        std::cerr << "listen() failed. (" << GETSOCKETERRNO() << ")" << std::endl;
		return false;
	}
    return true;

    printf("listen() end");
	/* accept any incoming connections */
}

bool accept()
{
    WSAPOLLFD fds[1];

    fds[0].fd = socket_listen;
    fds[0].events = POLLRDNORM;

    // Sockets, number of sockets, timeout (ms)
    int retCode = WSAPoll(fds, 1, 1);
    if (retCode == SOCKET_ERROR)
    {
        printf("Error occured, errno: %d", errno);
        return "";
    }
    else if (retCode == 0)
    {
        printf("Nothing yet.");
        // return "";
    }
    else
    {
        printf("Ready to accept");
    }




    std::cout << "acceptTCP() called" << std::endl;
	/* we have to store the clients connection info */
	/* the type will guarentee the type is large enough to hold this data */
	struct sockaddr_storage client_address;
	/* client len will differ depending on Ipv4/6*/
	socklen_t client_len = sizeof(client_address);
	/* now a tcp connection has been astablished */
    /* potentially blocking*/
	socket_client = accept(socket_listen,
		(struct sockaddr*) &client_address, &client_len);

	if (!ISVALIDSOCKET(socket_client)) {
        std::cerr << "accept() failed. (" << GETSOCKETERRNO() << ")" << std::endl;
		return false;
	}

	/* connection esablished, info */
	printf("Client is connected...");
	char address_buffer[100];

	/* client address, client address length (for ipv4 or 6), output buffer, and length, hostname output(leave so null), "", Flag specifies we dont want to see hostname of ip addresses */
	getnameinfo((struct sockaddr*)&client_address,
		client_len, address_buffer, sizeof(address_buffer), 0, 0,
		NI_NUMERICHOST);
	printf("%s\n", address_buffer);

    return true;
}


// Future method to send (DM to individual clients)
bool send(std::string _msg)
{
	// Call serializer here

    send(socket_client, _msg.c_str(), strlen(_msg.c_str()), 0);
	return true;
}

int main()
{
    // fd_set readSet;
    // for (int i = 0; i < 64; i++)
    // {
    //     SOCKET test = 0;
    //     int number = 12;
    //     readSet.fd_array[i] = test;
    //     readSet.fd_count = number;
    // }

    // Use poll, then we time out and check the next value. Small timeouts like 5ms between each check.
    // 
    // We should do a "a full check of each client should take max 1 second". I.e. 4 clients, 250ms each. 100 clients, 10 ms


    create("27011");
    listen(1);
	accept();

    // for(;;)
    // {
    //     std::this_thread::sleep_for(std::chrono::seconds(1));
    // }
    
    
    while(true)
    {
        std::string message;
        std::cout << "--> ";
        std::getline(std::cin, message);
        send(message);
        std::cout << "Sent: " << message << "\n" << std::endl;
    }


    return 0;
}


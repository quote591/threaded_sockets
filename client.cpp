// Networking headers
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

SOCKET socket_peer;
struct addrinfo* peer_address;

bool create(std::string hostName, std::string port)
{
	// Not filled in 
	if (hostName.c_str() == NULL || port.c_str() == NULL){
		return false;
	}

	// Set windows socket version
#ifdef _WIN32
	WSADATA d;
	if (WSAStartup(MAKEWORD(2, 2), &d)) {
		std::cerr << "Failed to initalize." << std::endl;
		return false;
	}
#endif

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	// TCP UDP(SOCK_DGRAM)
	hints.ai_socktype = SOCK_STREAM;
	// struct addrinfo* peer_address;
	if (getaddrinfo(hostName.c_str(), port.c_str(), &hints, &peer_address)) {
		std::cerr << "mTCP::ClientCreateTCP error.\ngetaddrinfo() failed. (" << GETSOCKETERRNO() << ")" << std::endl;
		return false;
	}

	printf("Remote address is: "); // TODO remove
	// Again variable arrays potentially
	char address_buffer[100];
	char service_buffer[100];
	getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen,
		address_buffer, sizeof(address_buffer),
		service_buffer, sizeof(service_buffer),
		NI_NUMERICHOST);
	printf("%s %s\n", address_buffer, service_buffer); // TODO remove

	// Create socket
	printf("Creating socket...\n");
	// SOCKET socket_peer;
	socket_peer = socket(peer_address->ai_family,
		peer_address->ai_socktype, peer_address->ai_protocol);
	if (!ISVALIDSOCKET(socket_peer)) {
		std::cerr << "mTCP::ClientCreateTCP error.\nsocket() failed. (" << GETSOCKETERRNO() << ")" << std::endl;
		return false;
	}
	return true;
}

bool connect()
{
	// Connect
	printf("Connecting...\n");
	
	if (connect(socket_peer,
		peer_address->ai_addr, peer_address->ai_addrlen)) {
		
		fprintf(stderr, "connect() failed. (%d)\n", GETSOCKETERRNO());
		return false;
	}
	freeaddrinfo(peer_address);

	printf("Connected.\n");
    
    return true;
}

std::string recv()
{	

    // Idea so far: (for server)
    // Main thread spools up worker thread.
    // Main thread then deals with displaying to screen and taking user input for sending.
    // 
    // Worker thread cycles through all handled connections. Any connections taht have waiting data
    // will be dealt with and their message will be put into a buffer which main thread will periodically
    // check to update the screen.
    //
    // Worker therad will also check a flag to see if there are any incoming connections. If so 
    // an async task will be spooled up to accept the connection and add it to connection list.
    //
    //


    // Using poll as this is used on both windwos and linux
    
    // typedef struct pollfd {
    //   SOCKET fd;
    //   SHORT  events;
    //   SHORT  revents; // Used as a return from WSAPoll, can tell result of oporation
    // } WSAPOLLFD, *PWSAPOLLFD, *LPWSAPOLLFD;
    WSAPOLLFD fds[1];

    fds[0].fd = socket_peer;
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
        return "";
    }
    else
    {
        printf("Data is available on the socket");
    }

	int read_buffer_size = 1024;
	// TODO // Maybe rethink this high performance C like code for more modern safe code
	// since we have recv and realloc which can both throw errors
	char* read_buffer = (char*)calloc(read_buffer_size, sizeof(char));

	int bytes_recived = 0;

    recv(socket_peer, read_buffer, 1024, 0);

	// do {
		
	// 	// Resize the read in buffer
	// 	if (bytes_recived >= read_buffer_size){
	// 		// Double input buffer size
	// 		read_buffer = (char*)realloc(read_buffer, read_buffer_size *= 2);
	// 	}
	// // Keep reading while there is data
	// } while ((bytes_recived = recv(socket_peer, read_buffer, 1024, 0)) > 0);

	std::string msg = read_buffer;
	free(read_buffer);

	return msg;
}

int main()
{
	// Main thead only deals with input.
	// Worker thread does everything else, send recv, poll etc.

	


    create("192.168.1.114", "27011");
    connect();
    while(true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::string msg = recv();
        if (msg.size() > 0)
            std::cout << msg << std::endl;
    }

    return 0;
}

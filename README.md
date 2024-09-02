Chat application with sockets and terminal based GUI for both Windows and Linux (eventually). 

<p align="center">
  <img src="https://github.com/user-attachments/assets/f8214d45-33d3-419c-92a4-158352d848f6"/width=570>
</p>
An example image of the terminal based chat application on Windows 10.


Written in C++17 using std::thread WinSock2 sockets.

# Building
Note the application will only work on `Windows` at this current moment. I have yet to port it over to Linux.

Building the client and server are done in the exact same way. They both have a CMake file.

Create the build directory in either the `src/client` or `src/server` root folders.
```
mkdir build; cd build
```
Then generate the cmake files and build
```
cmake ..
make
```
If using Windows MingGW with g++ compiler instead of MSVC (not been tested) use the following.
```
cmake -G "MinGW Makefiles" -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ ..
mingw32-make.exe
```

Then you can run the executable within the build folder. The client is called `main.exe` and the server is called `servermain.exe`

# Not working?

- If you are having issues with communicating you can first check the output log of either the client or server in the logs folder.

- If the client is not connecting then check the local IP address in the main.cpp of the client code. As this project is quite infant the IP address is hard coded. Change it to the servers ip address.

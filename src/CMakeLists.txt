cmake_minimum_required(VERSION 3.15)

project(TerminalGUIChat VERSION 1.0 DESCRIPTION "A terminal based GUI chat application.")

## Debug
set(CMAKE_BUILD_TYPE Debug)
## Wall
set(CMAKE_CXX_FLAGS "-Wall")

## C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

## BAD practice. Use the build.sh
## set(CMAKE_C_COMPILER "gcc")
## set(CMAKE_CXX_COMPILER "g++")

set(sourceFiles display.cpp messageHandler.cpp)
add_library(mainLib STATIC "${sourceFiles}")

add_executable(main main.cpp)
target_link_libraries(main mainLib)


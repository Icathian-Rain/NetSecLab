cmake_minimum_required(VERSION 3.16)
project(miniVPN)

set(CMAKE_CXX_STANDARD 14)

add_executable(miniVPN main.cpp  utils.cpp utils.h VPNServer.cpp VPNServer.h VPNClient.cpp VPNClient.h IPPool.cpp IPPool.h ThreadSafeQueue.h CLI11.hpp)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(miniVPN ssl crypto crypt Threads::Threads)
cmake_minimum_required(VERSION 3.10)
project(SecureWebPass)

set(CMAKE_CXX_STANDARD 17)

find_package(Boost 1.66
        REQUIRED
        COMPONENTS system)

if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    add_compile_options("-O0")
    add_compile_options("-mtune=native")
    add_executable(server src/main.cpp src/server_certificate.hpp src/http_server_async_ssl.hpp src/db_utils.hpp)
    target_link_libraries(server ${Boost_LIBRAIRIES} pthread crypto ssl sqlite3)
endif ()

if (WIN32)
    target_link_libraries(server wsock32 ws2_32)
endif ()
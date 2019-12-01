cmake_minimum_required(VERSION 3.12)
project(server)

set(CMAKE_CXX_STANDARD 17)


find_package(Boost 1.66
        REQUIRED
        COMPONENTS system)

if(Boost_FOUND)
    include_directories (${Boost_INCLUDE_DIRS})
    add_compile_options ("-O3")
    add_compile_options ("-mtune=native")
    add_executable(server src/http_server_async_ssl.cpp src/server_certificate.hpp)
    target_link_libraries(server ${Boost_LIBRAIRIES} pthread crypto ssl)
endif()
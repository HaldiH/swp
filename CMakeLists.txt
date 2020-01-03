cmake_minimum_required(VERSION 3.10)
project(SecureWebPass)

set(CMAKE_CXX_STANDARD 17)

add_compile_options("-O1")
add_compile_options("-mtune=native")

add_executable(server src/main.cpp src/server_db.cpp)
target_include_directories(server PUBLIC include)
target_link_libraries(server pthread crypto ssl sqlite3 argon2)

if (WIN32)
    target_link_libraries(server wsock32 ws2_32)
endif ()

find_package(Boost 1.66
        REQUIRED
        COMPONENTS system)

if (Boost_FOUND)
    target_include_directories(server PUBLIC ${Boost_INCLUDE_DIRS})
    target_link_libraries(server ${Boost_LIBRAIRIES})
endif ()

add_executable(tests test/main.cpp src/server_db.cpp)
target_include_directories(tests PUBLIC include)
target_link_libraries(tests argon2 pthread sqlite3)

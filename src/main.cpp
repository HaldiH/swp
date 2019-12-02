#include <iostream>
#include "db_utils.hpp"

int main(int argc, char *argv[]) {
    SWP::server server;
    SWP::server::setToken("Lorem ipsum dolor sit amet, consectetur adipiscing elit", "test");
    SWP::server::storePassword("Hello, World!", "test", "");
    for (const auto &v : SWP::server::getUserPasswords("test").value) {
        std::cout << "Password: " << v << std::endl;
    }
    for (const auto &v: SWP::server::getToken("test").value) {
        std::cout << "Token: " << v << std::endl;
    }
}
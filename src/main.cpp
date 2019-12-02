#include <iostream>
#include "db_utils.hpp"

int main(int argc, char *argv[]) {
    swp::ServerDB db;
    db.setToken("Lorem ipsum dolor sit amet, consectetur adipiscing elit", "test");
    db.storePassword("Hello, World!", "test", "");
    for (const auto &v : db.getUserPasswords("test").value) {
        std::cout << "Password: " << v << std::endl;
    }
    for (const auto &v: db.getToken("test").value) {
        std::cout << "Token: " << v << std::endl;
    }
}
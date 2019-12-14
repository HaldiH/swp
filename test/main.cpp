//
// Created by hugo on 09.12.19.
//

#include <string>
#include "server_db.hpp"

int main(int argc, char *argv[]) {
    swp::ServerDB db("server.db");
    std::string pwd = "password";
    db.registerUser("test", pwd);
    std::cout << argon2i_verify(db.getPasswordHash("test").c_str(), pwd.c_str(), pwd.size()) << std::endl;
    return 0;
}
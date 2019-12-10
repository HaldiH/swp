//
// Created by hugo on 09.12.19.
//

#include <string>
#include "db_utils.hpp"

int main(int argc, char *argv[]) {
    db.open("server.db");
    std::string pwd = "password";
    db.registerUser("test", pwd);
    std::cout << argon2i_verify(db.getPasswordHash("test").c_str(), pwd.c_str(), pwd.size()) << std::endl;
    return 0;
}
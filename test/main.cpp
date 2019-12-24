//
// Created by hugo on 09.12.19.
//

#include <string>
#include "server_db.hpp"

int main(int argc, char* argv[]) {
    swp::ServerDB db("server.db");
    std::string_view pwd1 = "password";
    std::string_view pwd2 = "hello";
    int rc = db.registerUser("test", pwd1);
    std::cout << rc << std::endl;
    rc = db.registerUser("test2", pwd2);
    std::cout << rc << std::endl;

    // Make request and first_row_request public before testing
    constexpr std::string_view sql = "SELECT * FROM users;";
    auto res = db.request(sql, std::vector<std::string_view>{});
    for (const auto& rows : res.value) {
        std::cout << "| ";
        for (const auto& col : rows) {
            std::cout << col << " | ";
        }
        std::cout << std::endl;
    }

    auto res2 = db.first_row_request(sql, 1, std::vector<std::string_view>{});
    std::cout << res2.first << std::endl;

    //    std::cout << argon2i_verify(db.getPasswordHash("test").c_str(), pwd.c_str(), pwd.size()) << std::endl;
    return 0;
}
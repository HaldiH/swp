//
// Created by hugo on 09.12.19.
//

#include <string>
#include "swp/server_db.hpp"

int main(int argc, char* argv[]) {
    swp::ServerDB db("server.db");
    int rc;

    db.cleanSessionID();
    std::string_view pwd1 = "password";
    std::string_view pwd2 = "hello";
    rc = db.registerUser("test", pwd1);
    std::cout << rc << std::endl;
    rc = db.registerUser("test2", pwd2);
    std::cout << rc << std::endl;
    rc = db.storeVault("test", "test_vault", swp::BLOB_Data{84, 101, 115, 116});
    std::cout << rc << std::endl;
    rc = db.storeVault("test", "test_vault2", swp::BLOB_Data{84, 101, 115, 116});
    std::cout << rc << std::endl;
    rc = db.storeVault("test", "test_vault3", swp::BLOB_Data{84, 101, 115, 116});
    std::cout << rc << std::endl;
    rc = db.updateVault("test_vault", "test", swp::BLOB_Data{72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33});
    std::cout << rc << std::endl;
//    auto data = db.getVault("test", "test_vault").first;
//    std::cout << std::string(data.begin(), data.end());

    // Make request and firstRowColumn public before testing
    /*constexpr std::string_view sql = "SELECT * FROM users;";
    auto res = db.request(sql, std::vector<std::string_view>{});
    for (const auto& rows : res.value) {
        std::cout << "| ";
        for (const auto& col : rows) {
            std::cout << col << " | ";
        }
        std::cout << std::endl;
    }

    auto res2 = db.firstRowColumn(sql, 1, std::vector<std::string_view>{});
    std::cout << res2.first << std::endl;*/

    //    std::cout << argon2i_verify(db.getPasswordHash("test").c_str(), pwd.c_str(), pwd.size()) << std::endl;

    return 0;
}
#pragma once

#include <iostream>
#include <string>
#include <sqlite3.h>
#include <vector>
#include <array>

namespace swp {
    template<class T>
    struct SecValue {
        std::vector<std::vector<T>> value;
        int sqlite_code;
    };

    class ServerDB {
    public:
        ServerDB() = default;

        explicit ServerDB(const char *filename) {
            int rc = open(filename);
            if (rc != SQLITE_OK)
                std::cerr << "Can't initialize tables: " << sqlite3_errmsg(db) << std::endl;
        }

        ~ServerDB() {
            int rc;
            rc = sqlite3_close_v2(db);
            if (rc != SQLITE_OK)
                std::cerr << "Can't close database: " << sqlite3_errmsg(db) << std::endl;
        }

        int open(const char *filename) {
            int rc;
            rc = sqlite3_open(filename, &db);
            if (rc)
                std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;

            const std::string sql = "CREATE TABLE IF NOT EXISTS `users` ("
                                    "`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
                                    "`username` TEXT NOT NULL,"
                                    "`token` CHAR(50) );"
                                    "CREATE TABLE IF NOT EXISTS `passwords` ("
                                    "`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
                                    "`owner` TEXT NOT NULL,"
                                    "`group` TEXT,"
                                    "`hash` TEXT NOT NULL );";
            rc = exec_request(sql);
            return rc;
        }

        SecValue<std::string> getToken(const std::string &username) {
            const std::string sql = "SELECT `token` FROM users WHERE username='" + username + "'";
            return select_request<std::string>(sql, 0);
        }

        int setToken(const std::string &token, const std::string &username) {
            const std::string sql = "INSERT INTO users ('username','token') "
                                    "VALUES ('" +
                                    username + "','" + token + "');";
            return exec_request(sql);
        }

        bool tokenMatch(const std::string &username, const std::string &token_to_check) {
            auto res = getToken(username);
            if (res.sqlite_code != SQLITE_OK)
                return false;
            for (auto const &v : res.value) {
                if (v[0] == token_to_check)
                    return true;
            }
            return false;
        }

//        int storePassword(const Hash *hash, const std::string &username, const std::string &group) {
//            auto const error = [&](int rc) {
//                std::cerr << sqlite3_errmsg(db) << std::endl;
//                return rc;
//            };
//            int rc;
//            sqlite3_stmt *stmt = nullptr;
//            const std::string sql = "INSERT INTO `passwords` ('owner','hash','group') "
//                                    "VALUES ('" +
//                                    username + "', ?, '" + group + "');";
//            rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
//            if (rc != SQLITE_OK)
//                return error(rc);
//            rc = sqlite3_bind_blob(stmt, 1, hash, hash_size, SQLITE_STATIC);
//            if (rc != SQLITE_OK)
//                return error(rc);
//            rc = sqlite3_step(stmt);
//            if (rc != SQLITE_DONE)
//                return error(rc);
//            sqlite3_finalize(stmt);
//            return rc;
//        }

//        SecValue<Hash> getUserPasswords(const std::string &username) {
//            const std::string sql = "SELECT hash FROM passwords WHERE `owner`='" + username + "';";
//            return select_request<Hash>(sql, 0);
//        }

        std::string getHash(const std::string &username) {
            const std::string sql = "SELECT `hash` FROM passwords WHERE `owner`='" + username + "';";
            return select_row_request(sql, 0);
        }

//        bool passwordCheck(const std::string &username, const Hash req_hash) {
//            const std::string sql = "SELECT `hash` FROM passwords WHERE `owner`='" + username + "';";
//
//            auto const error = [&](int rc) {
//                std::cerr << sqlite3_errmsg(db) << std::endl;
//                return false;
//            };
//            int rc;
//            sqlite3_stmt *stmt = nullptr;
//            rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
//            if (rc != SQLITE_OK)
//                return error(rc);
//            rc = sqlite3_step(stmt);
//            if (rc != SQLITE_DONE)
//                return error(rc);
//            auto sq_hash = static_cast<const char *>(sqlite3_column_blob(stmt, 0));
//            auto sq_len = sqlite3_column_bytes(stmt, 0);
//            rc = sqlite3_finalize(stmt);
//            return rc == SQLITE_OK && std::equal(sq_hash, sq_hash + sq_len, req_hash.begin(), req_hash.end());
//        }

    private:
        sqlite3 *db{};

        int exec_request(const std::string &sql) {
            char *zErrMsg;

            int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &zErrMsg);
            if (rc != SQLITE_OK)
                std::cerr << zErrMsg << std::endl;
            return rc;
        }

        template<class T>
        SecValue<T> select_request(const std::string &sql, int iCol) {
            int rc;
            sqlite3_stmt *stmt = nullptr;
            rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
            if (rc != SQLITE_OK) {
                std::cerr << sqlite3_errmsg(db) << std::endl;
                return SecValue<T>{std::vector<std::vector<T>>{}, SQLITE_ERROR};
            }
            std::vector<std::vector<T>> rows{};
            while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
                std::vector<T> columns{};
                for (int i = 0; i <= iCol; i++) {
                    columns.emplace_back((reinterpret_cast<const char *>(sqlite3_column_text(stmt, i))));
                }
                rows.emplace_back(columns);
            }

            SecValue<T> value = {rows, rc};

            sqlite3_finalize(stmt);
            return value;
        }

        std::string select_row_request(const std::string &sql, int iCol) {
            int rc;
            sqlite3_stmt *stmt = nullptr;
            rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
            if (rc != SQLITE_OK) {
                std::cerr << sqlite3_errmsg(db) << std::endl;
                return "NULL";
            }
            rc = sqlite3_step(stmt);
            if (rc != SQLITE_ROW)
                return "NULL";
            const std::string row = reinterpret_cast<const char *>(sqlite3_column_text(stmt, iCol));
            sqlite3_finalize(stmt);
            return row;
        }
    };
}

inline swp::ServerDB db;

#pragma once

#include <iostream>
#include <string>
#include <sqlite3.h>
#include <vector>
#include <array>
#include <argon2.h>
#include <cstring>

#include "session_id.hpp"

#define HASHLEN 32
#define SALTLEN 16
#define ENCLEN 4 * HASHLEN

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
                                    "`password` TEXT NOT NULL,"
                                    "`token` TEXT,"
                                    "`session_ids` TEXT );"
                                    "CREATE TABLE IF NOT EXISTS `passwords` ("
                                    "`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
                                    "`owner` TEXT NOT NULL,"
                                    "`group` TEXT);";
            rc = exec_request(sql);
            return rc;
        }

        [[nodiscard]] SecValue<std::string> getToken(const std::string &username) const {
            const std::string sql = "SELECT `token` FROM users WHERE username='" + username + "'";
            return select_request<std::string>(sql, 0);
        }

        int setToken(const std::string &token, const std::string &username) {
            const std::string sql = "INSERT INTO users ('username','token') "
                                    "VALUES ('" +
                                    username + "','" + token + "');";
            return exec_request(sql);
        }

        [[nodiscard]] bool tokenMatch(const std::string &username, const std::string &token_to_check) const {
            auto res = getToken(username);
            if (res.sqlite_code != SQLITE_OK)
                return false;
            for (auto const &v : res.value) {
                if (v[0] == token_to_check)
                    return true;
            }
            return false;
        }

        int setSessionID(const SessionID<SESSIONID_SIZE> sessionId, const std::string &username) {
            const std::string sql =
                    "UPDATE users SET `session_ids`='" + std::string(sessionId.view()) + "' WHERE `username`='" +
                    username + "';";
            return exec_request(sql);
        }

        int setPassword(const std::string &username, const std::string &password) {
            const std::string sql =
                    "UPDATE users SET `password`='" + getEncodedPassword(password) + "' WHERE `username`='" + username +
                    "';";
            return exec_request(sql);
        }

        int registerUser(const std::string &username, const std::string &password) {
            const std::string sql = "INSERT INTO users (username,password) VALUES ('" + username + "','" +
                                    getEncodedPassword(password) + "');";
            return exec_request(sql);
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

        [[nodiscard]]

        std::string getPasswordHash(const std::string &username) const {
            const std::string sql = "SELECT `password` FROM users WHERE `username`='" + username + "';";
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
                std::cerr << sqlite3_errmsg(db) << std::endl;
            return rc;
        }

        template<class T>
        [[nodiscard]] SecValue<T> select_request(const std::string &sql, int iCol) const {
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

        [[nodiscard]] std::string select_row_request(const std::string &sql, int iCol) const {
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

        [[nodiscard]] static std::string getEncodedPassword(const std::string &password) {
            auto getSalt = [] {
                static auto gen = [] {
                    std::random_device rd;
                    std::seed_seq sseq({(int) rd(), (int) std::time(nullptr)});
                    return std::mt19937_64{sseq};
                }();

                std::array<std::uint8_t, SALTLEN> ret{};
                static_assert(SALTLEN % 8 == 0);
                for (int i = 0; i < SALTLEN / 8; ++i) {
                    const auto rval = gen();
                    std::memcpy(ret.data() + i * 8, &rval, sizeof(rval));
                }
                return ret;
            };

            std::string encoded;
            encoded.resize(ENCLEN);

            uint32_t t_cost = 3;            // 1-pass computation
            uint32_t m_cost = (1 << 16);      // 64 mebibytes memory usage
            uint32_t parallelism = 1;       // number of threads and lanes

            int rc;
            rc = argon2i_hash_encoded(t_cost, m_cost, parallelism, password.c_str(), password.size(), getSalt().data(), SALTLEN,
                                      HASHLEN, encoded.data(), ENCLEN);
            if (rc != ARGON2_OK) {
                std::cerr << "Error occurred while encoding password: " << rc << std::endl;
                return "NULL";
            }
            encoded.erase(encoded.find('\0'));
            return encoded;
        }
    };
}

inline swp::ServerDB db;

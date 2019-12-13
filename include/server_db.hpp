#pragma once

#include <iostream>
#include <string>
#include <sqlite3.h>
#include <vector>
#include <array>
#include <argon2.h>
#include <cstring>
#include <boost/asio/deadline_timer.hpp>

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
        ServerDB();

        explicit ServerDB(const char *filename);

        ~ServerDB();

        int open(const char *filename);

        [[nodiscard]] SecValue<std::string> getToken(const std::string &username) const;

        int setToken(const std::string &token, const std::string &username);

        [[nodiscard]] bool tokenMatch(const std::string &username, const std::string &token_to_check) const;

        int setSessionID(SessionID<SESSIONID_SIZE> sessionId, const std::string &username);

        [[nodiscard]] std::string getSessionIDs(const std::string &username) const;

        bool checkSessionID(const std::string &username, const std::string &session_id);

        int setPassword(const std::string &username, const std::string &password);

        int registerUser(const std::string &username, const std::string &password);

        [[nodiscard]] std::string getPasswordHash(const std::string &username) const;

    private:
        sqlite3 *db{};

        int exec_request(const std::string &sql);

        template<class T>
        [[nodiscard]] SecValue<T> select_request(const std::string &sql, int iCol) const;

        [[nodiscard]] std::string select_row_request(const std::string &sql, int iCol) const;

        [[nodiscard]] static std::string getEncodedPassword(const std::string &password);
    };
}

inline swp::ServerDB db;

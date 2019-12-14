#pragma once

#include <array>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <argon2.h>
#include <boost/asio/deadline_timer.hpp>
#include <sqlite3.h>
#include "session_id.hpp"

namespace swp {
constexpr auto HASHLEN = 32;
constexpr auto SALTLEN = 16;
constexpr auto ENCLEN = 4 * HASHLEN;

template <class T> struct SecValue {
    std::vector<std::vector<T>> value;
    int sqlite_code;
};

class ServerDB {
  public:
    ServerDB() = default;

    explicit ServerDB(const char* filename);

    ~ServerDB();

    int open(const char* filename);

    [[nodiscard]] SecValue<std::string> getToken(const std::string& username);

    int setToken(const std::string& token, const std::string& username);

    [[nodiscard]] bool tokenMatch(const std::string& username, const std::string& token_to_check);

    int setSessionID(SessionID<SESSIONID_SIZE> sessionId, const std::string& username);

    [[nodiscard]] std::string getSessionIDs(const std::string& username);

    bool checkSessionID(const std::string& username, const std::string& session_id);

    int setPassword(const std::string& username, const std::string& password);

    int registerUser(const std::string& username, const std::string& password);

    [[nodiscard]] std::string getPasswordHash(const std::string& username);

  private:
    sqlite3* db{};

    int exec_request(const std::string& sql);

    SecValue<std::string> select_request(const std::string& sql, const std::vector<std::string>& args);

    std::pair<std::string, int> select_row_request(const std::string& sql, int iCol, const std::vector<std::string>& args);

    [[nodiscard]] static std::string getEncodedPassword(const std::string& password);
};
} // namespace swp

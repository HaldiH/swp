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

    [[nodiscard]] SecValue<std::string_view> getToken(std::string_view username);

    int setToken(std::string_view token, std::string_view username);

    [[nodiscard]] bool tokenMatch(std::string_view username, std::string_view token_to_check);

    int setSessionID(SessionID<SESSIONID_SIZE> sessionId, std::string_view username);

    bool checkSessionID(std::string_view username, std::string_view session_id);

    int setPassword(std::string_view username, std::string_view password);

    int registerUser(std::string_view username, std::string_view password);

    [[nodiscard]] std::string_view getPasswordHash(std::string_view username);

  private:
    sqlite3* db{};

    int exec_request(std::string_view sql);

    SecValue<std::string_view> select_request(std::string_view sql, std::vector<std::string_view> args);

    std::pair<std::string_view, int> select_row_request(std::string_view sql, int iCol, std::vector<std::string_view> args);

    [[nodiscard]] std::string getEncodedPassword(std::string_view password);
};
} // namespace swp

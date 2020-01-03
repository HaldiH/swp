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

using BLOB_Data = std::vector<uint8_t>;

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

    [[nodiscard]] SecValue<std::string> getToken(std::string_view username);

    int setToken(std::string_view token, std::string_view username);

    [[nodiscard]] bool tokenMatch(std::string_view username, std::string_view token_to_check);

    int setSessionID(SessionID<SESSIONID_SIZE> sessionId, std::string_view username);

    [[nodiscard]] bool isSessionIdValid(std::string_view username, std::string_view session_id);

    int cleanSessionID();

    int setPassword(std::string_view username, std::string_view password);

    int registerUser(std::string_view username, std::string_view password);

    [[nodiscard]] std::string getPasswordHash(std::string_view username);

    [[nodiscard]] std::vector<std::string> listVault(std::string_view owner);

    [[nodiscard]] std::pair<BLOB_Data, int> getVault(std::string_view owner, std::string_view vault_name);

    int storeVault(std::string_view username, std::string_view vault_name, const BLOB_Data& data);

    int updateVault(std::string_view vault_name, std::string_view owner, const BLOB_Data& data);

    int deleteVault(std::string_view vault_name, std::string_view owner);

  private:
    sqlite3* db{};

    int error(int rc);

    int exec_request(std::string_view sql);

    SecValue<std::string> request(std::string_view sql, const std::vector<std::string_view>& args);

    std::pair<std::string, int> first_row_request(std::string_view sql, int iCol, const std::vector<std::string_view>& args);

    [[nodiscard]] static std::pair<std::string, int> getEncodedPassword(std::string_view password);
};
} // namespace swp

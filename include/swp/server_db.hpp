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
constexpr auto SESSIONID_SIZE = 128;
constexpr auto TOKEN_SIZE = 128;
template <std::size_t N, class = std::enable_if_t<(N % 8) == 0>> using Token = SessionId<N>;

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

    [[nodiscard]] SecValue<std::string> listToken(std::string_view owner);

    [[nodiscard]] std::pair<std::string, int> getToken(std::string_view owner, std::string_view token_name);

    int setToken(Token<TOKEN_SIZE> token, std::string_view owner, std::string_view name);

    int deleteToken(std::string_view owner, std::string_view token);

    [[nodiscard]] bool isTokenValid(std::string_view owner, std::string_view token);

    int setSessionID(SessionId<SESSIONID_SIZE> sessionId, std::string_view username);

    [[nodiscard]] bool isSessionIdValid(std::string_view username, std::string_view session_id);

    int cleanSessionID();

    int setPassword(std::string_view username, std::string_view password);

    int registerUser(std::string_view username, std::string_view password);

    [[nodiscard]] std::string getPasswordHash(std::string_view username);

    [[nodiscard]] std::pair<std::vector<std::string>, int> listVault(std::string_view owner);

    [[nodiscard]] std::pair<BLOB_Data, int> getVault(std::string_view owner, std::string_view vault_name);

    int storeVault(std::string_view username, std::string_view vault_name, const BLOB_Data& data);

    int updateVault(std::string_view vault_name, std::string_view owner, const BLOB_Data& data);

    int deleteVault(std::string_view vault_name, std::string_view owner);

  private:
    sqlite3* db{};

    int error(int rc);

    int exec_request(std::string_view sql);

    SecValue<std::string> request(std::string_view sql, const std::vector<std::string_view>& args);

    std::pair<std::string, int> firstRowColumn(std::string_view sql, int iCol, const std::vector<std::string_view>& args);

    template <class T> std::pair<std::vector<T>, int> singleColumnList(std::string_view sql, int iCol, const std::vector<std::string_view>& args);

    template <class T> std::pair<std::vector<T>, int> firstRow(std::string_view sql, const std::vector<std::string_view>& args);

    int setTokenLastUsage(std::string_view owner, std::string_view token);

    [[nodiscard]] static std::pair<std::string, int> getEncodedHash(std::string_view password);
};
} // namespace swp

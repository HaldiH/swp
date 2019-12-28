//
// Created by hugo on 13.12.19.
//
#include "server_db.hpp"

namespace swp {
using namespace std::literals;

int ServerDB::error(int rc) {
    std::cerr << sqlite3_errmsg(db) << std::endl;
    return rc;
}

ServerDB::ServerDB(const char* filename) {
    int rc = open(filename);
    if (rc != SQLITE_OK)
        std::cerr << "Can't initialize tables: " << sqlite3_errmsg(db) << std::endl;
}

ServerDB::~ServerDB() {
    int rc;
    rc = sqlite3_close_v2(db);
    if (rc != SQLITE_OK)
        std::cerr << "Can't close database: " << sqlite3_errmsg(db) << std::endl;
}

int ServerDB::open(const char* filename) {
    int rc;
    if (rc = sqlite3_open(filename, &db); rc != SQLITE_OK) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return rc;
    }

    constexpr auto sql = "CREATE TABLE IF NOT EXISTS `users` ("
                         "`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
                         "`username` TEXT NOT NULL UNIQUE,"
                         "`password` TEXT NOT NULL,"
                         "`token` TEXT);"
                         "CREATE TABLE IF NOT EXISTS `vaults` ("
                         "`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
                         "`name` TEXT NOT NULL,"
                         "`owner` TEXT NOT NULL,"
                         "`group` TEXT,"
                         "`data` BLOB,"
                         "UNIQUE ( `name`, `owner` ) ON CONFLICT FAIL);"
                         "CREATE TABLE IF NOT EXISTS `session_ids` ("
                         "`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
                         "`owner` TEXT NOT NULL,"
                         "`value` TEXT NOT NULL,"
                         "`creation_date` TEXT NOT NULL,"
                         "`expiration_date` TEXT NOT NULL);"sv;
    rc = exec_request(sql.data());
    if (rc != SQLITE_OK)
        std::cerr << "Can't create tables: " << sqlite3_errmsg(db) << std::endl;
    return rc;
}

[[nodiscard]] SecValue<std::string> ServerDB::getToken(std::string_view username) {
    constexpr auto sql = "SELECT `token` FROM users WHERE username = ?"sv;
    return request(sql.data(), std::vector<std::string_view>{});
}

int ServerDB::setToken(std::string_view token, std::string_view username) {
    constexpr auto sql = "INSERT INTO users ('username','token') "
                         "VALUES (?,?);"sv;
    return first_row_request(sql.data(), 0, std::vector<std::string_view>{username, token}).second;
}

[[nodiscard]] bool ServerDB::tokenMatch(std::string_view username, std::string_view token_to_check) {
    auto res = getToken(username);
    if (res.sqlite_code != SQLITE_OK)
        return false;
    for (auto const& v : res.value) {
        if (v[0] == token_to_check)
            return true;
    }
    return false;
}

int ServerDB::setSessionID(SessionID<SESSIONID_SIZE> sessionId, std::string_view username) {
    constexpr auto sql = "INSERT INTO session_ids (`owner`,`value`,`creation_date`,`expiration_date`) "
                         "VALUES (?,?,datetime('now'),datetime('now','+1 hour'));"sv;
    return first_row_request(sql.data(), 0, std::vector<std::string_view>{username, sessionId.view().data()}).second;
}

bool ServerDB::checkSessionID(std::string_view username, std::string_view session_id) {
    constexpr auto sql = "SELECT `value` FROM session_ids WHERE `owner` = ? AND `value` = ? AND DATETIME(`expiration_date`) > DATETIME('now')"sv;
    const auto value = first_row_request(sql.data(), 0, std::vector<std::string_view>{username, session_id});
    if (value.second != 0)
        return false;
    return !value.first.empty();
}

int ServerDB::setPassword(std::string_view username, std::string_view password) {
    constexpr auto sql = "UPDATE users SET `password` = ? WHERE `username` = ?;"sv;
    return first_row_request(sql.data(), 0, std::vector<std::string_view>{password, username}).second;
}

int ServerDB::registerUser(std::string_view username, std::string_view password) {
    constexpr auto sql = "INSERT INTO users (username,password) VALUES (?,?);"sv;
    auto value = getEncodedPassword(password);
    if (value.second != 0)
        return value.second;
    return first_row_request(sql.data(), 0, std::vector<std::string_view>{username, value.first}).second;
}

[[nodiscard]] std::string_view ServerDB::getPasswordHash(std::string_view username) {
    constexpr auto sql = "SELECT `password` FROM users WHERE `username` = ?;"sv;
    return first_row_request(sql.data(), 0, std::vector<std::string_view>{username}).first;
}

[[nodiscard]] std::pair<BLOB_Data, int> ServerDB::getVault(std::string_view username, std::string_view vault_name) {
    const auto err = [&](int rc) { return std::make_pair(BLOB_Data{}, error(rc)); };
    constexpr auto sql = "SELECT `data` FROM vaults WHERE `owner` = ? AND `name` = ?;"sv;
    int rc;
    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db, sql.data(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
        return err(rc);
    rc = sqlite3_bind_text(stmt, 1, username.data(), username.size(), SQLITE_STATIC);
    if (rc != SQLITE_OK)
        return err(rc);
    rc = sqlite3_bind_text(stmt, 2, vault_name.data(), vault_name.size(), SQLITE_STATIC);
    if (rc != SQLITE_OK)
        return err(rc);
    rc = sqlite3_step(stmt);
    if (!(rc == SQLITE_DONE || rc == SQLITE_ROW))
        return err(rc);

    const auto size = sqlite3_column_bytes(stmt, 0);
    const auto* blob = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 0));
    BLOB_Data data(blob, blob + size);

    rc = sqlite3_finalize(stmt);
    return std::make_pair(data, rc);
}

int ServerDB::storeVault(std::string_view username, std::string_view vault_name, const BLOB_Data& data) {
    constexpr auto sql = "INSERT INTO vaults (name,owner,data) VALUES (?,?,?);"sv;
    int rc;
    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db, sql.data(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
        return error(rc);
    if ((rc = sqlite3_bind_text(stmt, 1, vault_name.data(), vault_name.size(), SQLITE_STATIC)) != SQLITE_OK ||
        (rc = sqlite3_bind_text(stmt, 2, username.data(), username.size(), SQLITE_STATIC)) != SQLITE_OK ||
        (rc = sqlite3_bind_blob(stmt, 3, data.data(), data.size(), SQLITE_STATIC)) != SQLITE_OK)
        return error(rc);
    rc = sqlite3_step(stmt);
    if (!(rc == SQLITE_DONE || rc == SQLITE_ROW))
        return error(rc);
    rc = sqlite3_finalize(stmt);
    return rc;
}

int ServerDB::updateVault(std::string_view vault_name, std::string_view owner, const BLOB_Data& data) {
    constexpr auto sql = "UPDATE vaults SET `data` = ? WHERE `name` = ? AND `owner` = ?;"sv;
    int rc;
    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db, sql.data(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
        return error(rc);
    if ((rc = sqlite3_bind_text(stmt, 2, vault_name.data(), vault_name.size(), SQLITE_STATIC)) != SQLITE_OK ||
        (rc = sqlite3_bind_text(stmt, 3, owner.data(), owner.size(), SQLITE_STATIC)) != SQLITE_OK ||
        (rc = sqlite3_bind_blob(stmt, 1, data.data(), data.size(), SQLITE_STATIC)) != SQLITE_OK)
        return error(rc);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
        return error(rc);
    if (sqlite3_changes(db) <= 0) {
        std::cerr << "Cannot find the requested vault" << std::endl;
        return rc;
    }
    return sqlite3_finalize(stmt);
}

int ServerDB::exec_request(std::string_view sql) {
    char* zErrMsg{};
    const int rc = sqlite3_exec(db, sql.data(), nullptr, nullptr, &zErrMsg);
    if (rc != SQLITE_OK)
        return error(rc);
    return rc;
}

SecValue<std::string> ServerDB::request(std::string_view sql, const std::vector<std::string_view>& args) {
    auto const err = [&](int rc) { return SecValue<std::string>{std::vector<std::vector<std::string>>{}, error(rc)}; };
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql.data(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
        return err(rc);
    {
        int i = 0;
        for (auto& arg : args) {
            rc = sqlite3_bind_text(stmt, ++i, arg.data(), arg.size(), nullptr);
            if (rc != SQLITE_OK)
                return err(rc);
        }
    }

    std::vector<std::vector<std::string>> rows{};
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        std::vector<std::string> columns{};
        auto nCol = sqlite3_column_count(stmt);
        columns.reserve(nCol);
        for (int i = 0; i < nCol; i++) {
            if (const auto tmp = sqlite3_column_text(stmt, i); tmp)
                columns.emplace_back(reinterpret_cast<const char*>(tmp));
        }
        rows.emplace_back(std::move(columns));
    }
    rc = sqlite3_finalize(stmt);
    SecValue<std::string> value{std::move(rows), rc};
    return std::move(value);
}

std::pair<std::string, int> ServerDB::first_row_request(std::string_view sql, int iCol, const std::vector<std::string_view>& args) {
    const auto err = [&](int rc) { return std::make_pair(std::string{}, error(rc)); };
    int rc;
    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db, sql.data(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
        return err(rc);
    int i = 1;
    for (auto arg : args) {
        rc = sqlite3_bind_text(stmt, i++, arg.data(), arg.size(), nullptr);
        if (rc != SQLITE_OK)
            return err(rc);
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW)
        return err(rc);
    auto tmp = sqlite3_column_text(stmt, iCol);
    std::string row = tmp ? reinterpret_cast<const char*>(tmp) : std::string{};
    rc = sqlite3_finalize(stmt);
    return make_pair(move(row), rc);
}

[[nodiscard]] std::pair<std::string, int> ServerDB::getEncodedPassword(std::string_view password) {
    auto const err = [&](int rc) {
        std::cerr << "Error occurred while encoding password: " << rc << std::endl;
        return make_pair(std::string{}, rc);
    };
    auto getSalt = [] {
        static thread_local auto gen = [] {
            std::random_device rd;
            std::seed_seq sseq({(int)rd(), (int)std::time(nullptr)});
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

    uint32_t t_cost = 3;         // 1-pass computation
    uint32_t m_cost = (1 << 16); // 64 mebibytes memory usage
    uint32_t parallelism = 1;    // number of threads and lanes

    int rc = argon2i_hash_encoded(t_cost, m_cost, parallelism, password.data(), password.size(), getSalt().data(), SALTLEN, HASHLEN, encoded.data(),
                                  ENCLEN);
    if (rc != ARGON2_OK)
        return err(rc);
    encoded.erase(encoded.find('\0'));
    return std::make_pair(std::move(encoded), rc);
}
} // namespace swp

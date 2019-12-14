//
// Created by hugo on 13.12.19.
//
#include "server_db.hpp"

namespace swp {
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

    const std::string sql = "CREATE TABLE IF NOT EXISTS `users` ("
                            "`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
                            "`username` TEXT NOT NULL UNIQUE,"
                            "`password` TEXT NOT NULL,"
                            "`token` TEXT);"
                            "CREATE TABLE IF NOT EXISTS `passwords` ("
                            "`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
                            "`owner` TEXT NOT NULL,"
                            "`group` TEXT);"
                            "CREATE TABLE IF NOT EXISTS `session_ids` ("
                            "`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
                            "`owner` TEXT NOT NULL,"
                            "`value` TEXT NOT NULL,"
                            "`creation_date` TEXT NOT NULL,"
                            "`expiration_date` TEXT NOT NULL);";
    rc = exec_request(sql);
    if (rc != SQLITE_OK)
        std::cerr << "Can't create tables: " << sqlite3_errmsg(db) << std::endl;
    return rc;
}

[[nodiscard]] SecValue<std::string> ServerDB::getToken(const std::string& username) {
    const std::string sql = "SELECT `token` FROM users WHERE username = ?";
    return select_request(sql, std::vector<std::string>{username});
}

int ServerDB::setToken(const std::string& token, const std::string& username) {
    const std::string sql = "INSERT INTO users ('username','token') "
                            "VALUES (?,?);";
    return select_row_request(sql, 0, std::vector<std::string>{username, token}).second;
}

[[nodiscard]] bool ServerDB::tokenMatch(const std::string& username, const std::string& token_to_check) {
    auto res = getToken(username);
    if (res.sqlite_code != SQLITE_OK)
        return false;
    for (auto const& v : res.value) {
        if (v[0] == token_to_check)
            return true;
    }
    return false;
}

int ServerDB::setSessionID(SessionID<SESSIONID_SIZE> sessionId, const std::string& username) {
    const std::string sql = "INSERT INTO session_ids (`owner`,`value`,`creation_date`,`expiration_date`) "
                            "VALUES (?,?,datetime('now'),datetime('now','+1 hour'));";
    return select_row_request(sql, 0, std::vector<std::string>{username, std::string(sessionId.view())}).second;
}

bool ServerDB::checkSessionID(const std::string& username, const std::string& session_id) {
    const std::string sql = "SELECT `value` FROM session_ids WHERE `owner` = ? AND `value` = ? AND DATETIME(`expiration_date`) > DATETIME('now')";
    const auto value = select_row_request(sql, 0, std::vector<std::string>{username, session_id});
    return !value.first.empty();
}

int ServerDB::setPassword(const std::string& username, const std::string& password) {
    const std::string sql = "UPDATE users SET `password` = ? WHERE `username` = ?;";
    return select_row_request(sql, 0, std::vector<std::string>{password, username}).second;
}

int ServerDB::registerUser(const std::string& username, const std::string& password) {
    const std::string sql = "INSERT INTO users (username,password) VALUES (?,?);";
    return select_row_request(sql, 0, std::vector<std::string>{username, getEncodedPassword(password)}).second;
}

[[nodiscard]] std::string ServerDB::getPasswordHash(const std::string& username) {
    const std::string sql = "SELECT `password` FROM users WHERE `username` = ?;";
    return select_row_request(sql, 0, std::vector<std::string>{username}).first;
}

int ServerDB::exec_request(const std::string& sql) {
    char* zErrMsg;
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &zErrMsg);
    if (rc != SQLITE_OK)
        std::cerr << sqlite3_errmsg(db) << std::endl;
    return rc;
}

SecValue<std::string> ServerDB::select_request(const std::string& sql, const std::vector<std::string>& args) {
    int rc;
    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << sqlite3_errmsg(db) << std::endl;
        return SecValue<std::string>{std::vector<std::vector<std::string>>{}, rc};
    }
    for (size_t i = 0; i < args.size(); i++) {
        auto& arg = args[i];
        rc = sqlite3_bind_text(stmt, i + 1, arg.c_str(), arg.size(), nullptr);
        if (rc != SQLITE_OK) {
            std::cerr << sqlite3_errmsg(db) << std::endl;
            return SecValue<std::string>{std::vector<std::vector<std::string>>{}, rc};
        }
    }
    std::vector<std::vector<std::string>> rows{};
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        std::vector<std::string> columns{};
        for (int i = 0; i < args.size(); i++) {
            if (auto tmp = sqlite3_column_text(stmt, i); tmp) {
                columns.emplace_back(reinterpret_cast<const char*>(tmp));
            }
        }
        rows.emplace_back(columns);
    }

    SecValue<std::string> value{std::move(rows), rc};

    sqlite3_finalize(stmt);
    return value;
}

std::pair<std::string, int> ServerDB::select_row_request(const std::string& sql, int iCol, const std::vector<std::string>& args) {
    int rc;
    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << sqlite3_errmsg(db) << std::endl;
        return std::pair{std::string{}, rc};
    }
    for (size_t i = 0; i < args.size(); i++) {
        auto& arg = args[i];
        rc = sqlite3_bind_text(stmt, i + 1, arg.data(), arg.size(), nullptr);
        if (rc != SQLITE_OK) {
            std::cerr << sqlite3_errmsg(db) << std::endl;
            return std::pair{std::string{}, rc};
        }
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        std::cerr << sqlite3_errmsg(db) << std::endl;
        return std::pair{std::string{}, rc};
    }
    std::string row = reinterpret_cast<const char*>(sqlite3_column_text(stmt, iCol));
    rc = sqlite3_finalize(stmt);
    return {move(row), rc};
}

[[nodiscard]] std::string ServerDB::getEncodedPassword(const std::string& password) {
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

    int rc;
    rc = argon2i_hash_encoded(t_cost, m_cost, parallelism, password.c_str(), password.size(), getSalt().data(), SALTLEN, HASHLEN, encoded.data(),
                              ENCLEN);
    if (rc != ARGON2_OK) {
        std::cerr << "Error occurred while encoding password: " << rc << std::endl;
        return "NULL";
    }
    encoded.erase(encoded.find('\0'));
    return encoded;
}
} // namespace swp

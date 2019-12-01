#include <iostream>
#include <string>
#include <sqlite3.h>

#define DBNAME "server.db"

sqlite3* openDataBase() {
    sqlite3* db;
    int rc;
    char* zErrMsg;

    rc = sqlite3_open(DBNAME, &db);

    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return nullptr;
    }

    std::cout << "Opened database successfully" << std::endl;
    return db;
}

const int initialize_tables() {
    sqlite3* db = openDataBase();
    char* zErrMsg;

    const std::string sql = "DROP TABLE IF EXISTS `users`;"
                            "CREATE TABLE `users` ("
                            "id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
                            "username TEXT NOT NULL,"
                            "token CHAR(50) );";

    int rc = sqlite3_exec(db, sql.c_str(), nullptr, 0, &zErrMsg);
    if (rc == SQLITE_OK)
        std::cout << "Initialized tables successfully" << std::endl;
    else
        std::cerr << "Cannot initialize tables: " << zErrMsg << std::endl;
    sqlite3_close(db);
    return rc;
}

std::string getToken(const std::string username) {
    sqlite3* db = openDataBase();
    if (!db)
        return "NULL";

    const std::string sql = "SELECT `token` FROM users WHERE username='" + username + "'";
    const std::string data = "Callback function called";

    int rc;
    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        std::cerr << "Prepare failed" << std::endl;
        sqlite3_close(db);
        return "NULL";
    }
    rc = sqlite3_step(stmt);
    auto v = sqlite3_column_text(stmt, 0);
    auto temp = std::string{(const char*)v};
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return std::string{temp};
}

const int setToken(const std::string token, const std::string username) {
    sqlite3* db = openDataBase();
    if (!db)
        return 1;

    char* zErrMsg;

    const std::string sql = "INSERT INTO users ('username','token') "
                            "VALUES ('" +
                            username + "','" + token + "');";
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, 0, &zErrMsg);
    if (rc == SQLITE_OK)
        std::cout << "Token attributed successfully" << std::endl;
    else
        std::cerr << "Cannot set token: " << zErrMsg << std::endl;
    sqlite3_close(db);
    return rc;
}
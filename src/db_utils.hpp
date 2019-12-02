#include <iostream>
#include <string>
#include <sqlite3.h>
#include <vector>

#define DBNAME "server.db"

namespace SWP {
    struct SecValue {
        std::vector<std::string> value;
        int sqlite_code;
    };

    class server {
    public:
        server() {
            const std::string sql = "CREATE TABLE IF NOT EXISTS `users` ("
                                    "`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
                                    "`username` TEXT NOT NULL,"
                                    "`token` CHAR(50) );"
                                    "CREATE TABLE IF NOT EXISTS `passwords` ("
                                    "`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
                                    "`owner` TEXT NOT NULL,"
                                    "`group` TEXT,"
                                    "`value` TEXT NOT NULL );";
            exec_request(sql);
        }

        static SecValue getToken(const std::string &username) {
            const std::string sql = "SELECT `token` FROM users WHERE username='" + username + "'";
            return select_request(sql);
        }

        static int setToken(const std::string &token, const std::string &username) {
            const std::string sql = "INSERT INTO users ('username','token') "
                                    "VALUES ('" +
                                    username + "','" + token + "');";
            return exec_request(sql);
        }

        static int storePassword(const std::string &value, const std::string &username, const std::string &group) {
            const std::string sql = "INSERT INTO `passwords` ('owner','value','group') "
                                    "VALUES ('" +
                                    username + "', '" + value + "', '" + group + "');";

            return exec_request(sql);
        }

        static SecValue getUserPasswords(const std::string &username) {
            const std::string sql = "SELECT value FROM passwords WHERE `owner`='" + username + "';";

            SecValue value = select_request(sql);
            return value;
        }

    private:
        static sqlite3 *openDataBase() {
            sqlite3 *db;
            int rc;

            rc = sqlite3_open(DBNAME, &db);

            if (rc) {
                std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
                return nullptr;
            }
            return db;
        }

        static int exec_request(const std::string &sql) {
            sqlite3 *db = openDataBase();
            if (!db)
                return SQLITE_ERROR;

            char *zErrMsg;

            int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &zErrMsg);
            if (rc != SQLITE_OK)
                std::cerr << zErrMsg << std::endl;
            sqlite3_close_v2(db);
            return rc;
        }

        static SecValue select_request(const std::string &sql) {
            sqlite3 *db = openDataBase();
            if (!db)
                return SecValue{std::vector<std::string>{}, SQLITE_ERROR};

            int rc;
            sqlite3_stmt *stmt = nullptr;
            rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
            if (rc != SQLITE_OK) {
                std::cerr << "Prepare failed" << std::endl;
                sqlite3_close(db);
                return SecValue{std::vector<std::string>{}, SQLITE_ERROR};
            }
            std::vector<std::string> vector{};
            while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
                vector.emplace_back((reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0))));

            SecValue value = {vector, rc};

            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return value;
        }
    };
}
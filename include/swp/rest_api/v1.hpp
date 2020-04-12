//
// Created by hugo on 4/12/20.
//

#pragma once
#include <boost/beast/version.hpp>
#include "tools.hpp"

class api_v1 {
  public:
    api_v1(http::request<http::string_body>&& req, swp::ServerDB& db) : req_(std::move(req)), db_(db) {}

  private:
    http::request<http::string_body>&& req_;
    swp::ServerDB& db_;

    http::response<http::string_body> response_builder(http::status status) {
        http::response<http::string_body> res{status, req_.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::access_control_allow_origin, "*");
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req_.keep_alive());
        return std::move(res);
    }

    http::response<http::string_body> preflight_response() {
        http::response<http::string_body> res{http::status::ok, req_.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::access_control_allow_origin, "*");
        res.set(http::field::access_control_allow_methods, "GET, POST, PATCH, DELETE");
        res.set(http::field::access_control_allow_headers, "*");
        res.set(http::field::access_control_max_age, 86400);
        res.keep_alive(req_.keep_alive());
        res.prepare_payload();
        return std::move(res);
    }

    http::response<http::string_body> error_builder(http::status status, boost::string_view body) {
        auto res = response_builder(status);
        res.body() = std::string(body);
        res.prepare_payload();
        return std::move(res);
    }

    http::response<http::string_body> ok_response() {
        auto res = response_builder(http::status::ok);
        res.prepare_payload();
        return std::move(res);
    }

  public:
    // Returns a bad request response
    http::response<http::string_body> bad_request(beast::string_view why) { return error_builder(http::status::bad_request, why); }

    http::response<http::string_body> method_not_allowed(beast::string_view target) {
        return error_builder(http::status::method_not_allowed, "The resource '" + std::string(target) + "' doesn't support the requested method.");
    }

    // Returns a not found response
    http::response<http::string_body> not_found() {
        return error_builder(http::status::not_found, "The resource '" + std::string(req_.target()) + "' was not found.");
    }

  private:
    http::response<http::string_body> unauthorized(boost::string_view target) {
        return error_builder(http::status::unauthorized, "The resource '" + std::string(target) + "' requires authorization.");
    }

    // Returns a server error response
    http::response<http::string_body> server_error(beast::string_view what) {
        return error_builder(http::status::internal_server_error, "An error occurred: '" + std::string(what) + "'");
    }

    bool is_authenticated(std::string_view username) {
        if (username.empty())
            return false;
        auto sessionId = bsv2sv(req_["Session-Id"]);
        auto token = bsv2sv(req_["X-Auth-Token"]);
        return db_.isSessionIdValid(username, sessionId) || db_.isTokenValid(username, token);
    }

    http::response<http::string_body> login(beast::string_view target) {
        if (req_.method() != http::verb::get)
            return method_not_allowed(req_.target());
        if (!target.empty())
            return not_found();
        auto username = bsv2sv(req_["Username"]);
        if (is_authenticated(username))
            return not_found();
        auto password = bsv2sv(req_["Password"]);
        if (username.empty() || password.empty() ||
            argon2i_verify(db_.getPasswordHash(username).data(), password.data(), password.size()) != ARGON2_OK)
            return unauthorized(req_.target());
        SessionId<swp::SESSIONID_SIZE> sessionId;
        if (db_.setSessionID(sessionId, username) != SQLITE_OK)
            return server_error("Cannot store session id.");
        auto res = response_builder(http::status::ok);
        res.set(http::field::set_cookie, "Session-Id=" + std::string(sessionId.view()));
        res.body() = std::string(sessionId.view());
        res.prepare_payload();
        return std::move(res);
    };

    http::response<http::string_body> register_(beast::string_view target) { return not_found(); }; // NOT implemented yet - WIP

    http::response<http::string_body> vault(beast::string_view target) {
        auto username = bsv2sv(req_["Username"]);
        if (!is_authenticated(username))
            return unauthorized(req_.target());
        switch (req_.method()) {
        case http::verb::get: {
            std::string buffer{};
            if (target.empty()) {
                auto vaults = db_.listVault(username);
                if (vaults.second != SQLITE_OK)
                    return server_error("Cannot load the user vaults.");
                for (auto& vault : vaults.first) {
                    buffer += vault + '\n';
                }
                auto res = response_builder(http::status::ok);
                res.body() = buffer;
                res.prepare_payload();
                return std::move(res);
            }
            auto vault = db_.getVault(username, bsv2sv(get_first_segment(target).segment()));
            if (vault.second != SQLITE_OK)
                return not_found();
            auto res = response_builder(http::status::ok);
            res.body() = std::string(vault.first.begin(), vault.first.end());
            res.prepare_payload();
            return std::move(res);
        }
        case http::verb::post: {
            if (!target.empty())
                return method_not_allowed(req_.target());
            auto vault_name = bsv2sv(req_["Vault-Name"]);
            if (vault_name.empty())
                return bad_request("Vault name cannot be empty.");
            auto body = req_.body();
            if (int rc = db_.storeVault(username, vault_name, swp::BLOB_Data(body.begin(), body.end())); rc != SQLITE_OK) {
                if (rc == SQLITE_CONSTRAINT)
                    return bad_request("The vault '" + std::string(vault_name) + "' already exists.");
                return server_error("Cannot store vault data.");
            }
            return ok_response();
        }
        case http::verb::delete_: {
            if (target.empty())
                return method_not_allowed(req_.target());
            if (target.empty())
                return method_not_allowed(req_.target());
            if (int rc = db_.deleteVault(bsv2sv(target), username); rc != SQLITE_OK)
                return server_error("Cannot delete the requested vault.");
            return ok_response();
        }
        case http::verb::patch: {
            if (target.empty())
                return method_not_allowed(req_.target());
            if (target.empty())
                return method_not_allowed(req_.target());
            auto body = req_.body();
            if (int rc = db_.updateVault(bsv2sv(target), username, swp::BLOB_Data(body.begin(), body.end())); rc != SQLITE_OK) {
                if (rc == SQLITE_DONE)
                    return bad_request("The vault '" + std::string(target) + "' doesn't exist.");
                return server_error("Cannot update the requested vault.");
            }
            return ok_response();
        }
        default:
            return method_not_allowed(req_.target());
        }
    };

    http::response<http::string_body> token(beast::string_view target) {
        auto username = bsv2sv(req_["Username"]);
        if (!is_authenticated(username))
            return unauthorized(req_.target());
        switch (req_.method()) {
        case http::verb::get: {
            if (!target.empty()) {
                if (!target.empty())
                    return method_not_allowed(req_.target());
            }
            auto tokens = db_.listToken(username);
            if (tokens.sqlite_code != SQLITE_OK)
                return server_error("Cannot load the username tokens.");
            auto res = response_builder(http::status::ok);
            std::string buffer{};
            for (const auto& row : tokens.value) {
                buffer += "Name: " + row[0] + '\n' + "Token: " + row[1] + '\n' + "Creation-Date: " + row[2] + '\n' + "Last-Usage: " + [&row] {
                    if (row.size() >= 4) {
                        if (const auto v = row[3]; !v.empty())
                            return row[3];
                    }
                    return std::string("N/A");
                }() + "\n\n";
            }
            res.body() = buffer;
            res.prepare_payload();
            return std::move(res);
        }
        case http::verb::post: {
            if (!target.empty()) {
                if (!target.empty())
                    return method_not_allowed(req_.target());
            }
            const auto token_name = bsv2sv(req_["Token-Name"]);
            if (token_name.empty())
                return bad_request("Token name cannot be empty.");
            swp::Token<swp::TOKEN_SIZE> token;
            if (db_.setToken(token, username, token_name) != SQLITE_OK)
                return server_error("Cannot set a token.");
            return ok_response();
        }
        case http::verb::delete_: {
            if (target.empty())
                return method_not_allowed(req_.target());
            if (db_.deleteToken(username, bsv2sv(target)) != SQLITE_OK)
                return server_error("Cannot delete the token.");
            return ok_response();
        }
        default:
            return method_not_allowed(req_.target());
        }
    };

    http::response<http::string_body> user(beast::string_view target) {
        if (handle_endpoint("token", &target))
            return token(target);
        return not_found();
    };

  public:
    http::response<http::string_body> v1(beast::string_view target) {
        if (req_.method() == http::verb::options)
            return preflight_response();
        if (handle_endpoint("login", &target))
            return login(target);
        if (handle_endpoint("register", &target))
            return register_(target);
        if (handle_endpoint("vault", &target))
            return vault(target);
        if (handle_endpoint("user", &target))
            return user(target);
        return not_found();
    };
};
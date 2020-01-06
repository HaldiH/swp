//
// Created by hugo on 02.01.20.
//

#ifndef SECUREWEBPASS_REQUEST_HANDLER_HPP
#define SECUREWEBPASS_REQUEST_HANDLER_HPP

#include <argon2.h>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/config.hpp>
#include "server_db.hpp"
#include "session_id.hpp"

namespace beast = boost::beast; // from <boost/beast.hpp>
namespace http = beast::http;   // from <boost/beast/http.hpp>

std::string_view bsv2sv(boost::string_view bsv) { return std::string_view(bsv.data(), bsv.size()); }

boost::string_view sv2bsv(std::string_view sv) { return boost::string_view(sv.data(), sv.size()); }

// Append an HTTP rel-path to a local filesystem path.
// The returned path is normalized for the platform.
std::string path_cat(beast::string_view base, beast::string_view path) {
    if (base.empty())
        return std::string(path);
    std::string result(base);
#ifdef BOOST_MSVC
    char constexpr path_separator = '\\';
    if (result.back() == path_separator)
        result.resize(result.size() - 1);
    result.append(path.data(), path.size());
    for (auto& c : result)
        if (c == '/')
            c = path_separator;
#else
    char constexpr path_separator = '/';
    if (result.back() == path_separator)
        result.resize(result.size() - 1);
    result.append(path.data(), path.size());
#endif
    return result;
}

// Return a reasonable mime type based on the extension of a file.
beast::string_view mime_type(beast::string_view path) {
    using beast::iequals;
    auto const ext = [&path] {
        auto const pos = path.rfind(".");
        if (pos == beast::string_view::npos)
            return beast::string_view{};
        return path.substr(pos);
    }();
    if (iequals(ext, ".htm"))
        return "text/html";
    if (iequals(ext, ".html"))
        return "text/html";
    if (iequals(ext, ".php"))
        return "text/html";
    if (iequals(ext, ".css"))
        return "text/css";
    if (iequals(ext, ".txt"))
        return "text/plain";
    if (iequals(ext, ".js"))
        return "application/javascript";
    if (iequals(ext, ".json"))
        return "application/json";
    if (iequals(ext, ".xml"))
        return "application/xml";
    if (iequals(ext, ".swf"))
        return "application/x-shockwave-flash";
    if (iequals(ext, ".flv"))
        return "video/x-flv";
    if (iequals(ext, ".png"))
        return "image/png";
    if (iequals(ext, ".jpe"))
        return "image/jpeg";
    if (iequals(ext, ".jpeg"))
        return "image/jpeg";
    if (iequals(ext, ".jpg"))
        return "image/jpeg";
    if (iequals(ext, ".gif"))
        return "image/gif";
    if (iequals(ext, ".bmp"))
        return "image/bmp";
    if (iequals(ext, ".ico"))
        return "image/vnd.microsoft.icon";
    if (iequals(ext, ".tiff"))
        return "image/tiff";
    if (iequals(ext, ".tif"))
        return "image/tiff";
    if (iequals(ext, ".svg"))
        return "image/svg+xml";
    if (iequals(ext, ".svgz"))
        return "image/svg+xml";
    return "application/text";
}

// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template <class Body, class Allocator, class Send>
void handle_request(beast::string_view doc_root, http::request<Body, http::basic_fields<Allocator>>&& req, Send&& send, swp::ServerDB& db) {
    auto const response_builder = [&req](http::status status) {
        http::response<http::string_body> res{status, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        return std::move(res);
    };

    auto const error_builder = [&response_builder](http::status status, boost::string_view body) {
        auto res = response_builder(status);
        res.body() = std::string(body);
        res.prepare_payload();
        return std::move(res);
    };

    auto const ok_response = [&response_builder] {
        auto res = response_builder(http::status::ok);
        res.prepare_payload();
        return std::move(res);
    };

    // Returns a bad request response
    auto const bad_request = [&error_builder](beast::string_view why) { return error_builder(http::status::bad_request, why); };

    auto const method_not_allowed = [&error_builder](beast::string_view target) {
        return error_builder(http::status::method_not_allowed, "The resource '" + std::string(target) + "' doesn't support the requested method.");
    };

    // Returns a not found response
    auto const not_found = [&error_builder](beast::string_view target) {
        return error_builder(http::status::not_found, "The resource '" + std::string(target) + "' was not found.");
    };

    auto const unauthorized = [&error_builder](boost::string_view target) {
        return error_builder(http::status::unauthorized, "The resource '" + std::string(target) + "' requires authorization.");
    };

    // Returns a server error response
    auto const server_error = [&error_builder](beast::string_view what) {
        return error_builder(http::status::internal_server_error, "An error occurred: '" + std::string(what) + "'");
    };

    auto const isAuthenticated = [&req, &db](std::string_view username) {
        if (username.empty())
            return false;
        auto sessionId = bsv2sv(req["Session-Id"]);
        auto token = bsv2sv(req["X-Auth-Token"]);
        return db.isSessionIdValid(username, sessionId) || db.isTokenValid(username, token);
    };

    auto const login = [&](beast::string_view target) {
        if (req.method() != http::verb::get)
            return method_not_allowed(req.target());
        if (!target.empty())
            return not_found(req.target());
        auto username = bsv2sv(req["Username"]);
        if (isAuthenticated(username))
            return not_found(req.target());
        auto password = bsv2sv(req["Password"]);
        if (username.empty() || password.empty() ||
            argon2i_verify(db.getPasswordHash(username).data(), password.data(), password.size()) != ARGON2_OK)
            return unauthorized(req.target());
        SessionId<swp::SESSIONID_SIZE> sessionId;
        if (db.setSessionID(sessionId, username) != SQLITE_OK)
            return server_error("Cannot store session id.");
        auto res = response_builder(http::status::ok);
        res.set(http::field::set_cookie, "Session-Id=" + std::string(sessionId.view()));
        res.prepare_payload();
        return std::move(res);
    };

    auto const register_ = [&](beast::string_view target) { return not_found(req.target()); }; // NOT implemented yet - WIP

    auto const vault = [&](beast::string_view target) {
        auto username = bsv2sv(req["Username"]);
        if (!isAuthenticated(username))
            return unauthorized(req.target());
        switch (req.method()) {
        case http::verb::get: {
            std::string buffer{};
            if (target.empty() || (target.starts_with('/') && target.substr(1).empty())) {
                auto vaults = db.listVault(username);
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
            if (!target.starts_with('/'))
                return not_found(req.target());
            auto vault_name = bsv2sv(target.substr(1));
            auto vault = db.getVault(username, vault_name);
            if (vault.second != SQLITE_OK)
                return not_found(req.target());
            auto res = response_builder(http::status::ok);
            res.body() = std::string(vault.first.begin(), vault.first.end());
            res.prepare_payload();
            return std::move(res);
        }
        case http::verb::post: {
            if (!(target.empty() || (target.starts_with('/') && target.substr(1).empty())))
                return method_not_allowed(req.target());
            auto vault_name = bsv2sv(req["Vault-Name"]);
            if (vault_name.empty())
                return bad_request("Vault name cannot be empty.");
            auto body = req.body();
            if (int rc = db.storeVault(username, vault_name, swp::BLOB_Data(body.begin(), body.end())); rc != SQLITE_OK) {
                if (rc == SQLITE_CONSTRAINT)
                    return bad_request("The vault '" + std::string(vault_name) + "' already exists.");
                return server_error("Cannot store vault data.");
            }
            return ok_response();
        }
        case http::verb::delete_: {
            if (target.empty())
                return method_not_allowed(req.target());
            if (!target.starts_with('/'))
                return not_found(req.target());
            target = target.substr(1);
            if (target.empty())
                return method_not_allowed(req.target());
            if (int rc = db.deleteVault(bsv2sv(target), username); rc != SQLITE_OK)
                return server_error("Cannot delete the requested vault.");
            return ok_response();
        }
        case http::verb::patch: {
            if (target.empty())
                return method_not_allowed(req.target());
            if (!target.starts_with('/'))
                return not_found(req.target());
            target = target.substr(1);
            if (target.empty())
                return method_not_allowed(req.target());
            auto body = req.body();
            if (int rc = db.updateVault(bsv2sv(target), username, swp::BLOB_Data(body.begin(), body.end())); rc != SQLITE_OK) {
                if (rc == SQLITE_DONE)
                    return bad_request("The vault '" + std::string(target) + "' doesn't exist.");
                return server_error("Cannot update the requested vault.");
            }
            return ok_response();
        }
        default:
            return method_not_allowed(req.target());
        }
    };

    auto const token = [&](beast::string_view target) {
        auto username = bsv2sv(req["Username"]);
        if (!isAuthenticated(username))
            return unauthorized(req.target());
        switch (req.method()) {
        case http::verb::get: {
            if (!target.empty()) {
                if (!target.starts_with('/'))
                    return not_found(req.target());
                if (!target.substr(1).empty())
                    return method_not_allowed(req.target());
            }
            auto tokens = db.listToken(username);
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
                if (!target.starts_with('/'))
                    return not_found(req.target());
                if (!target.substr(1).empty())
                    return method_not_allowed(req.target());
            }
            const auto token_name = bsv2sv(req["Token-Name"]);
            if (token_name.empty())
                return bad_request("Token name cannot be empty.");
            swp::Token<swp::TOKEN_SIZE> token;
            if (db.setToken(token, username, token_name) != SQLITE_OK)
                return server_error("Cannot set a token.");
            return ok_response();
        }
        case http::verb::delete_: {
            if (!target.starts_with('/'))
                return not_found(req.target());
            target = target.substr(1);
            if (target.empty())
                return method_not_allowed(req.target());
            if (db.deleteToken(username, bsv2sv(target)) != SQLITE_OK)
                return server_error("Cannot delete the token.");
            return ok_response();
        }
        default:
            return method_not_allowed(req.target());
        }
    };

    auto const user = [&](beast::string_view target) {
        if (constexpr beast::string_view key = "/token"; target.starts_with(key))
            return token(target.substr(key.size()));
        return not_found(req.target());
    };

    auto const api = [&](beast::string_view target) {
        if (constexpr beast::string_view key = "/login"; target.starts_with(key))
            return login(target.substr(key.size()));
        if (constexpr beast::string_view key = "/register"; target.starts_with(key))
            return register_(target.substr(key.size()));
        if (constexpr beast::string_view key = "/vault"; target.starts_with(key))
            return vault(target.substr(key.size()));
        if (constexpr beast::string_view key = "/user"; target.starts_with(key))
            return user(target.substr(key.size()));
        return not_found(req.target());
    };

    // Request path must be absolute and not contain "..".
    if (req.target().empty() || req.target()[0] != '/' || req.target().find("..") != beast::string_view::npos)
        return send(bad_request("Illegal request-target"));

    if (constexpr beast::string_view key = "/api"; req.target().starts_with(key))
        return send(api(req.target().substr(key.size())));

    // Build the path to the requested file
    std::string path = path_cat(doc_root, req.target());
    if (req.target().back() == '/')
        path.append("index.html");

    // Attempt to open the file
    beast::error_code ec;
    http::file_body::value_type body;
    body.open(path.c_str(), beast::file_mode::scan, ec);

    // Handle the case where the file doesn't exist
    if (ec == beast::errc::no_such_file_or_directory)
        return send(not_found(req.target()));

    // Handle an unknown error
    if (ec)
        return send(server_error(ec.message()));

    // Cache the size since we need it after the move
    auto const size = body.size();

    // Respond to HEAD request
    if (req.method() == http::verb::head) {
        http::response<http::empty_body> res{http::status::ok, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, mime_type(path));
        res.content_length(size);
        res.keep_alive(req.keep_alive());
        return send(std::move(res));
    }

    // Respond to GET request
    http::response<http::file_body> res{std::piecewise_construct, std::make_tuple(std::move(body)), std::make_tuple(http::status::ok, req.version())};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, mime_type(path));
    res.content_length(size);
    res.keep_alive(req.keep_alive());
    return send(std::move(res));
}

#endif // SECUREWEBPASS_REQUEST_HANDLER_HPP

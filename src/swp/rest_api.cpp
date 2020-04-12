//
// Created by hugo on 4/11/20.
//

#include "swp/rest_api.hpp"
#include "swp/rest_api/v1.hpp"
#include "session_id.hpp"

http::response<http::string_body> api_handler(http::request<http::string_body>&& req, swp::ServerDB& db) {
    std::cout << req.method() << " " << req.target() << " HTTP/" << req.version() / 10 << "." << req.version() % 10 << std::endl;

    // Request path must be absolute and not contain "..".
    if (req.target().empty() || req.target()[0] != '/' || req.target().find("..") != beast::string_view::npos)
        return api_v1(std::move(req), db).bad_request("Illegal request-target");

    if (auto sub_path = req.target(); handle_endpoint("api", &sub_path)) {
        if (handle_endpoint("v1", &sub_path))
            return api_v1(std::move(req), db).v1(sub_path);
        return api_v1(std::move(req), db).v1(sub_path);
    }

    //    if (constexpr beast::string_view key = "/api"; req.target().starts_with(key))
    //        return api_v1(req.target().substr(key.size()));
    return api_v1(std::move(req), db).not_found();
}

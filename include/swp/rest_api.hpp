//
// Created by hugo on 4/12/20.
//

#pragma once

#include <boost/beast/http.hpp>
#include "swp/server_db.hpp"

namespace beast = boost::beast; // from <boost/beast.hpp>
namespace http = beast::http;   // from <boost/beast/http.hpp>

http::response<http::string_body> api_handler(http::request<http::string_body>&& req, swp::ServerDB& db);
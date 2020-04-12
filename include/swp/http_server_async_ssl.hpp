//
// Created by hugo on 4/11/20.
//

#pragma once

#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include "swp/server_db.hpp"

namespace beast = boost::beast;   // from <boost/beast.hpp>
namespace net = boost::asio;      // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>

// Accepts incoming connections and launches the sessions
class listener : public std::enable_shared_from_this<listener> {
    net::io_context& ioc_;
    ssl::context& ctx_;
    tcp::acceptor acceptor_;
    std::shared_ptr<std::string const> doc_root_;
    std::reference_wrapper<swp::ServerDB> db;

  public:
    listener(net::io_context& ioc, ssl::context& ctx, const tcp::endpoint& endpoint, std::shared_ptr<std::string const> doc_root, swp::ServerDB& db);

    // Start accepting incoming connections
    void run();

  private:
    void do_accept();

    void on_accept(beast::error_code ec, tcp::socket socket);
};

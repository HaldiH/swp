#pragma once

#include <boost/asio/ssl/context.hpp>
#include <boost/filesystem/fstream.hpp>
#include <sstream>

namespace bfs = boost::filesystem;

namespace swp {

    /*
        To generate the self-signed certificates, use OpenSSL:

        openssl dhparam -out dh.pem 4096
        openssl req -newkey rsa:4096 -nodes -keyout key.pem -x509 -days 10000 -out cert.pem -subj "/C=US/ST=CA/L=Los Angeles/O=Beast/CN=www.example.com"
    */

    struct pki_path {
        std::string cert, key, dh;
    };

    inline void load_server_certificate(boost::asio::ssl::context &ctx, const pki_path &pkiPath) {
        const auto getFileData = [](const std::string &path) {
            bfs::path p{path};
            bfs::ifstream ifs{p};
            std::stringstream strStream;
            strStream << ifs.rdbuf();
            std::string data = strStream.str();
            ifs.close();
            return data;
        };
        const std::string cert = getFileData(pkiPath.cert);
        const std::string key = getFileData(pkiPath.key);
        const std::string dh = getFileData(pkiPath.dh);

        ctx.set_password_callback(
                [](std::size_t,
                   boost::asio::ssl::context_base::password_purpose) {
                    return "test";
                });

        ctx.set_options(
                boost::asio::ssl::context::default_workarounds |
                boost::asio::ssl::context::no_sslv2 |
                boost::asio::ssl::context::single_dh_use);

        ctx.use_certificate_chain(
                boost::asio::buffer(cert.data(), cert.size()));

        ctx.use_private_key(
                boost::asio::buffer(key.data(), key.size()),
                boost::asio::ssl::context::file_format::pem);

        ctx.use_tmp_dh(
                boost::asio::buffer(dh.data(), dh.size()));
    }
}
#include <iostream>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/path.hpp>
#include "http_server_async_ssl.hpp"
#include "server_db.hpp"

constexpr auto DATABASE_FILENAME = "server.db";

namespace bfs = boost::filesystem;

using namespace std::literals;

inline void load_server_certificate(boost::asio::ssl::context& ctx, std::string_view cert_path, std::string_view key_path, std::string_view dh_path) {
    constexpr auto getFileData = [](std::string_view path) {
        bfs::path p{path.data()};
        bfs::ifstream ifs{p};
        std::stringstream strStream;
        strStream << ifs.rdbuf();
        std::string data = strStream.str();
        ifs.close();
        return data;
    };
    auto const cert = getFileData(cert_path);
    auto const key = getFileData(key_path);
    auto const dh = getFileData(dh_path);

    if (cert.empty() || key.empty() || dh.empty()) {
        std::cerr << "One or more certificate files cannot be found" << std::endl;
        exit(124);
    }

    ctx.set_password_callback([](std::size_t, boost::asio::ssl::context_base::password_purpose) { return "test"; });

    ctx.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::single_dh_use);

    ctx.use_certificate_chain(boost::asio::buffer(cert.data(), cert.size()));

    ctx.use_private_key(boost::asio::buffer(key.data(), key.size()), boost::asio::ssl::context::file_format::pem);

    ctx.use_tmp_dh(boost::asio::buffer(dh.data(), dh.size()));
}

int main(int argc, char* argv[]) {
    swp::ServerDB db(DATABASE_FILENAME);
    auto const address = net::ip::make_address("0.0.0.0");
    auto const port = static_cast<unsigned short>(8080);
    auto const doc_root = std::make_shared<std::string>(".");
    auto const threads = std::max<int>(1, atoi(argv[4])); // NOLINT(cert-err34-c)
    auto constexpr cert_path = "cert.pem"sv, key_path = "key.pem"sv, dh_path = "dh.pem"sv;

    // The io_context is required for all I/O
    net::io_context ioc{threads};

    // The SSL context is required, and holds certificates
    ssl::context ctx{ssl::context::tlsv12};

    // This holds the self-signed certificate used by the server
    load_server_certificate(ctx, cert_path, key_path, dh_path);

    // Create and launch a listening port
    std::make_shared<listener>(ioc, ctx, tcp::endpoint{address, port}, doc_root, db)->run();

    // Run the I/O service on the requested number of threads
    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for (auto i = threads - 1; i > 0; --i)
        v.emplace_back([&ioc] { ioc.run(); });

    std::cout << "Server listening on " << address.to_string() << ":" << port << " with " << threads << " thread";
    if (threads > 1)
        std::cout << "s" << std::endl;
    std::cout << std::endl << "Serving " << doc_root->c_str() << std::endl;

    ioc.run();

    return EXIT_SUCCESS;
}

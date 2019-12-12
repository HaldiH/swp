#include <iostream>
#include "server_db.hpp"
#include "http_server_async_ssl.hpp"

int main(int argc, char *argv[]) {
    db.open("server.db");
    auto const address = net::ip::make_address("0.0.0.0");
    auto const port = static_cast<unsigned short>(8080);
    auto const doc_root = std::make_shared<std::string>(".");
    auto const threads = std::max<int>(1, atoi(argv[4])); // NOLINT(cert-err34-c)
    auto const cert_path = "cert.pem", key_path = "key.pem", dh_path = "dh.pem";
    const swp::pki_path pkiPath{cert_path, key_path, dh_path};

    std::cout << "Server listening on " << address.to_string() << ":" << port << " with " << threads;
    if (threads == 1)
        std::cout << " thread";
    else
        std::cout << " threads";
    std::cout << std::endl
              << "Serving " << doc_root.get()->c_str() << std::endl;

    // The io_context is required for all I/O
    net::io_context ioc{threads};

    // The SSL context is required, and holds certificates
    ssl::context ctx{ssl::context::tlsv12};

    // This holds the self-signed certificate used by the server
    load_server_certificate(ctx, pkiPath);

    // Create and launch a listening port
    std::make_shared<listener>(ioc, ctx, tcp::endpoint{address, port}, doc_root)->run();

    // Run the I/O service on the requested number of threads
    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for (auto i = threads - 1; i > 0; --i)
        v.emplace_back([&ioc] { ioc.run(); });
    ioc.run();

    return EXIT_SUCCESS;
}

//
// Created by hugo on 08.12.19.
//

#ifndef SECUREWEBPASS_HEX_HPP
#define SECUREWEBPASS_HEX_HPP

#include <string_view>
#include <array>

namespace hex {
    using namespace std::literals;

    using Hash = std::array<uint8_t, 256>;
    constexpr auto hash_size = sizeof(Hash);

    constexpr Hash hex_decode_id(std::string_view sv) noexcept {
        Hash ret{};
        auto sv_it = sv.begin();
        for (auto &b : ret) {
            if (sv_it == sv.end())
                break;

            for (auto r = false; !r; r = !r) {
                if (r)
                    b <<= 4u;
                const char c = *sv_it++;
                if (c >= '0' && '9' >= c)
                    b += c - '0';
                else if (c >= 'A' && 'F' >= c)
                    b += c - 'A' + 10;
                else if (c >= 'a' && 'f' >= c)
                    b += c - 'a' + 10;
            }
        }
        return ret;
    }

    constexpr auto hex_encode_id(Hash id) noexcept {
        constexpr auto hex = "0123456789abcdef"sv;
        std::array<char, hash_size * 2 + 1> ret = {};
        auto it = ret.begin();
        for (auto v : id) {
            *it++ = hex[(v >> 4) & 0xfu];
            *it++ = hex[v & 0xfu];
        }
        ret.back() = '\0';
        return ret;
    }
}

#endif //SECUREWEBPASS_HEX_HPP

//
// Created by hugo on 09.12.19.
//

#ifndef SECUREWEBPASS_SESSION_ID_HPP
#define SECUREWEBPASS_SESSION_ID_HPP

#include <array>
#include <ctime>
#include <iostream>
#include <random>
#include <string_view>

constexpr auto SESSIONID_SIZE = 128;

constexpr auto mk_printable(uint8_t bits) -> char {
    constexpr std::string_view table = "0123465789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=-";
    static_assert(table.size() == 64);
    return table[+bits];
}

template <std::size_t N, class = std::enable_if_t<(N % 8) == 0>> class SessionID {
    inline static std::ranlux48 eng;
    inline static bool eng_init = false;

    std::array<char, N> storage{};

  public:
    SessionID() {
        if (!eng_init) {
            eng_init = true;
            std::random_device rd;
            std::seed_seq sseq({(int)rd(), (int)std::time(nullptr)});
            eng = std::ranlux48{sseq};
        }

        for (int i = 0; i < (N / 8); ++i) {
            auto bits = eng();
            for (int j = 0; j < 8; ++j) {
                storage[i * 8 + j] = mk_printable(static_cast<uint8_t>(bits & 0x3f));
                bits >>= 6;
            }
        }
    }

    [[nodiscard]] constexpr std::string_view view() const noexcept { return {storage.data(), storage.size()}; }
};

#endif // SECUREWEBPASS_SESSION_ID_HPP

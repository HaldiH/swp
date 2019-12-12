#pragma once

#include <array>
#include <string_view>

namespace base64 {

    std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    constexpr std::array inverse = {
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //   0-15
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //  16-31
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, //  32-47
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, //  48-63
            -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, //  64-79
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, //  80-95
            -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, //  96-111
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, // 112-127
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 128-143
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 144-159
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 160-175
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 176-191
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 192-207
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 208-223
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 224-239
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1  // 240-255
    };



/// Returns max chars needed to encode a base64 string
    constexpr std::size_t encoded_size(std::size_t n) noexcept {
        return 4 * ((n + 2) / 3);
    }

/// Returns max bytes needed to decode a base64 string
    constexpr std::size_t decoded_size(std::size_t n) noexcept {
        return ((n & 3) == 0) ? (n / 4 * 3) : (3 * n / 4);
    }

/** Encode a series of octets as a padded, base64 string.

    The resulting string will not be null terminated.

    @par Requires

    The memory pointed to by `out` points to valid memory
    of at least `encoded_size(len)` bytes.

    @return The number of characters written to `out`. This
    will exclude any null termination.
*/
    constexpr std::size_t encode(char* dest, const char* src, std::size_t len) noexcept {
        char*      out = dest;
        const char* in = src;
        const auto tab = base64::alphabet;

        for(auto n = len / 3; n--;) {
            *out++ = tab[ (in[0] & 0xfc) >> 2];
            *out++ = tab[((in[0] & 0x03) << 4) + ((in[1] & 0xf0) >> 4)];
            *out++ = tab[((in[2] & 0xc0) >> 6) + ((in[1] & 0x0f) << 2)];
            *out++ = tab[  in[2] & 0x3f];
            in += 3;
        }

        switch(len % 3) {
            case 2:
                *out++ = tab[ (in[0] & 0xfc) >> 2];
                *out++ = tab[((in[0] & 0x03) << 4) + ((in[1] & 0xf0) >> 4)];
                *out++ = tab[                         (in[1] & 0x0f) << 2];
                *out++ = '=';
                break;

            case 1:
                *out++ = tab[ (in[0] & 0xfc) >> 2];
                *out++ = tab[((in[0] & 0x03) << 4)];
                *out++ = '=';
                *out++ = '=';
                break;

            case 0:
                break;
        }

        return out - static_cast<char*>(dest);
    }

/** Decode a padded base64 string into a series of octets.

    @par Requires

    The memory pointed to by `out` points to valid memory
    of at least `decoded_size(len)` bytes.

    @return The number of octets written to `dest`
*/
    constexpr std::size_t decode(unsigned char* dest, const char* src, std::size_t len) noexcept {
        auto out = dest;
        auto in = src;
        unsigned char c3[3]{}, c4[4]{};
        int i = 0;
        int j = 0;

        auto const inverse = base64::inverse;

        while(len-- && *in != '=') {
            auto const v = inverse[static_cast<unsigned char>(*in)];
            if(v == -1)
                break;
            ++in;
            c4[i] = v;
            if(++i == 4) {
                c3[0] =  (c4[0]        << 2) + ((c4[1] & 0x30) >> 4);
                c3[1] = ((c4[1] & 0xf) << 4) + ((c4[2] & 0x3c) >> 2);
                c3[2] = ((c4[2] & 0x3) << 6) +   c4[3];

                for(i = 0; i < 3; ++i)
                    *out++ = c3[i];
                i = 0;
            }
        }

        if(i) {
            c3[0] = ( c4[0]        << 2) + ((c4[1] & 0x30) >> 4);
            c3[1] = ((c4[1] & 0xf) << 4) + ((c4[2] & 0x3c) >> 2);
            c3[2] = ((c4[2] & 0x3) << 6) +   c4[3];

            for(j = 0; j < i - 1; ++j)
                *out++ = c3[j];
        }

        return out - dest;
    }

/* Note: the returned array is null-terminated for easier use with C-string functions */
    template <std::size_t N, std::size_t M = encoded_size(N)>
    constexpr auto encode(const std::array<char, N>& src) noexcept {
        std::array<char, M + 1> ret{};
        auto res = encode(ret.data(), src.data(), N);
        ret[M] = '\0';
        return ret;
    }

    template <std::size_t N, std::size_t M = encoded_size(N)>
    std::string encode_str(const std::array<char, N>& src) noexcept {
        std::string ret{};
        ret.resize(M);
        ret.resize(encode(ret.data(), src.data(), N));
        return ret;
    }

    template <std::size_t N, std::size_t M = decoded_size(N)>
    constexpr auto decode(const std::array<char, N> src) noexcept {
        std::array<unsigned char, M> ret{};
        auto res = decode(ret.data(), src.data(), N);
        return ret;
    }


    template <std::size_t N, std::size_t M = decoded_size(N)>
    constexpr auto decode(std::string_view src) noexcept {
        struct {
            std::array<unsigned char, M> buf;
            std::size_t real_len = 0;
        } ret{};
        ret.real_len = decode(ret.buf.data(), src.data(), N);
        return ret;
    }

} // base64
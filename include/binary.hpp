//
// Created by hugo on 08.12.19.
//

#ifndef SECUREWEBPASS_BINARY_HPP
#define SECUREWEBPASS_BINARY_HPP

#include <array>
#include <bitset>
#include <iostream>

namespace binary {
template <std::size_t N> constexpr auto encode(const std::array<char, N>& bytes) {
    unsigned char mask = 1; // Bit mask
    unsigned char bits[N][8] = {};

    // Extract the bits
    for (uint8_t i = 0; i < N; i++) {
        for (uint8_t j = 0; j < 8; j++) {
            // Mask each bit in the byte and store it
            bits[j] = (bytes[i] & (mask << j)) != 0;
        }
    }

    // For debug purposes, lets print the received data
    for (unsigned char byte[8] : bytes) {
        for (unsigned char bit : byte) {
            std::cout << bit << std::endl;
        }
    }
    return bits;
}

template <size_t N> void printBinary(const char src[N]) {
    for (size_t i = 0; i < N; i += 1) {
        std::cout << std::bitset<8>(src[i]);
    }
    std::cout << std::endl;
}
} // namespace binary

#endif // SECUREWEBPASS_BINARY_HPP

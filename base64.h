#pragma once

#include <array>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>
#include <string_view>

inline std::string base64_encode(std::string_view input) {
    if (input.empty())
        return {};

    const size_t input_length  = input.length();
    const size_t output_length = 4 * ((input_length + 2) / 3);

    std::string output(output_length, '\0');

    auto encoded_length = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(output.data()),
                                          reinterpret_cast<const unsigned char *>(input.data()), static_cast<int>(input_length));

    if (encoded_length != static_cast<int>(output_length)) {
        throw std::runtime_error("Encoding error: predicted " + std::to_string(output_length) + " but got " +
                                 std::to_string(encoded_length));
    }

    return output;
}

inline std::array<unsigned char, 44> base64_encode(const std::array<unsigned char, 32> &input) {
    constexpr size_t input_length  = 32;
    constexpr size_t output_length = 44; // ceil(32 / 3) * 4 = 44

    std::array<unsigned char, output_length> output;

    auto encoded_length = EVP_EncodeBlock(output.data(), input.data(), static_cast<int>(input_length));

    if (encoded_length != static_cast<int>(output_length)) {
        throw std::runtime_error("Encoding error: predicted " + std::to_string(output_length) + " but got " +
                                 std::to_string(encoded_length));
    }

    return output;
}

inline std::string base64_decode(std::string_view input) {
    if (input.empty())
        return {};

    const size_t input_length  = input.length();
    const size_t output_length = 3 * input_length / 4;

    std::string output(output_length, '\0');

    auto decoded_length = EVP_DecodeBlock(reinterpret_cast<unsigned char *>(output.data()),
                                          reinterpret_cast<const unsigned char *>(input.data()), static_cast<int>(input_length));

    if (decoded_length != static_cast<int>(output_length)) {
        throw std::runtime_error("Decoding error: predicted " + std::to_string(output_length) + " but got " +
                                 std::to_string(decoded_length));
    }

    // Remove padding if present
    while (!output.empty() && output.back() == '\0') {
        output.pop_back();
    }

    return output;
}

inline std::array<unsigned char, 33> base64_decode(const std::array<unsigned char, 44> &input) {
    constexpr size_t input_length  = 44;
    constexpr size_t output_length = 32 + 1; // ceil(44 / 4) * 3 = 33

    std::array<unsigned char, output_length> output;

    auto decoded_length = EVP_DecodeBlock(output.data(), input.data(), static_cast<int>(input_length));

    if (decoded_length != static_cast<int>(output_length)) {
        throw std::runtime_error("Decoding error: predicted " + std::to_string(output_length) + " but got " +
                                 std::to_string(decoded_length));
    }

    return output;
}

template <size_t N> inline std::string_view make_sha_view(const std::array<unsigned char, N> &input) {
    return std::string_view(reinterpret_cast<const char *>(input.data()), input.size());
}

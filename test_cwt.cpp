#include "../include/cwt.h"

#include <cassert>
#include <fmt/base.h>
#include <fmt/ranges.h>
#include <fmt/std.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string>
#include <string_view>
#include <vector>

using json = nlohmann::json;

// COSE_Sign = [
//        Headers,
//        payload : bstr / nil,
//        signatures : [+ COSE_Signature]
//    ]

// Split into 2 functions
auto verify_and_decode_cwt(const std::vector<uint8_t> &cwt, std::basic_string_view<unsigned char> public_key) {
    // Parse CWT
    json cwt_json = json::from_cbor(cwt);

    if (!cwt_json.is_array() || cwt_json.size() != 3) {
        throw std::runtime_error("Invalid CWT format");
    }

    // Extract components
    auto header_cbor  = cwt_json[0].get<std::vector<uint8_t>>();
    auto payload_cbor = cwt_json[1].get<std::vector<uint8_t>>();
    auto signature    = cwt_json[2].get<std::vector<uint8_t>>();

    auto header  = json::from_cbor(header_cbor);
    auto payload = json::from_cbor(payload_cbor);

    // Prepare data to verify
    std::vector<uint8_t> data_to_verify;
    data_to_verify.reserve(header_cbor.size() + payload_cbor.size());
    data_to_verify.insert(data_to_verify.end(), header_cbor.begin(), header_cbor.end());
    data_to_verify.insert(data_to_verify.end(), payload_cbor.begin(), payload_cbor.end());

    // Verify signature
    if (!verify_es256(data_to_verify, signature, public_key)) {
        throw std::runtime_error("Signature verification failed");
    }

    return payload;
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    auto [private_key, public_key] = generate_es256_key_pair();

    fmt::print("Public key:\n{}\n", public_key);
    fmt::print("Private key:\n{}\n", private_key);

    // Create a sample CWT
    json header  = {{"alg", "ES256"}};
    json payload = {{"iss", "auth0"}, {"sub", "1234567890"}, {"aud", "client_id"}};

    std::vector<uint8_t> header_cbor  = json::to_cbor(header);
    std::vector<uint8_t> payload_cbor = json::to_cbor(payload);

    // Prepare data to sign
    std::vector<uint8_t> data_to_sign;
    data_to_sign.reserve(header_cbor.size() + payload_cbor.size());
    data_to_sign.insert(data_to_sign.end(), header_cbor.begin(), header_cbor.end());
    data_to_sign.insert(data_to_sign.end(), payload_cbor.begin(), payload_cbor.end());

    // Sign the data
    std::vector<uint8_t> signature = sign_es256(data_to_sign, private_key);
    assert(!signature.empty());

    json                 cwt_json = json::array({header_cbor, payload_cbor, signature});
    std::vector<uint8_t> cwt      = json::to_cbor(cwt_json);

    try {
        std::basic_string_view<unsigned char> public_key_view(reinterpret_cast<const unsigned char *>(public_key.data()),
                                                              public_key.size());

        json decoded_payload = verify_and_decode_cwt(cwt, public_key_view);
        std::cout << "Decoded payload: " << decoded_payload.dump(2) << std::endl;
    } catch (const std::exception &e) { std::cerr << "Error: " << e.what() << std::endl; }

    // Clean up OpenSSL
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
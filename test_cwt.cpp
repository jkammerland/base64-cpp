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
#include <random>
#include <string>
#include <string_view>
#include <vector>

using json = nlohmann::json;

// COSE_Sign = [
//        Headers,
//        payload : bstr / nil,
//        signatures : [+ COSE_Signature]
//    ]

// TODO: Split into 2 functions
auto verify_and_decode_cwt(const std::vector<uint8_t> &cwt, std::string_view public_key) -> json;

void test_brute_force_attack() {
    auto [private_key, public_key] = generate_es256_key_pair();
    auto s                         = signer(std::string_view(private_key));
    auto v                         = verifier(std::string_view(public_key));

    // Create a sample CWT
    json header  = {{"alg", "ES256"}};
    json payload = {{"iss", "auth0"}, {"sub", "1234567890"}, {"aud", "client_id"}, {"prm", "admin"}};

    // Sign the cbor data
    std::vector<uint8_t> header_cbor  = json::to_cbor(header);
    std::vector<uint8_t> payload_cbor = json::to_cbor(payload);
    auto                 signature    = s.sign(header_cbor, payload_cbor);

    // Sanity check by verifying the signature
    assert(v.verify(*signature, header_cbor, payload_cbor));

    // Prepare a fake signature, sanity check second verify works, i.e no lingering state
    std::vector<uint8_t> fake_signature = *signature;
    assert(v.verify(fake_signature, header_cbor, payload_cbor));

    // Make random number generator
    std::random_device                     rd;
    std::mt19937                           gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);

    // Brute force attack
    for (size_t i = 0; i < 1e6; i++) {
        std::generate(fake_signature.begin(), fake_signature.end(), [&dis, &gen]() { return dis(gen); });
        assert(!v.verify(fake_signature, header_cbor, payload_cbor));
    }
    fmt::print("Brute force attack test passed\n");
}

int main() {
    auto [private_key, public_key] = generate_es256_key_pair();
    auto s                         = signer(std::string_view(private_key));
    auto v                         = verifier(std::string_view(public_key));

    fmt::print("Public key:\n{}\n", public_key);
    fmt::print("Private key:\n{}\n", private_key);

    // Create a sample CWT
    json header  = {{"alg", "ES256"}};
    json payload = {{"iss", "auth0"}, {"sub", "1234567890"}, {"aud", "client_id"}};

    std::vector<uint8_t> header_cbor  = json::to_cbor(header);
    std::vector<uint8_t> payload_cbor = json::to_cbor(payload);
    auto                 signature0   = s.sign(header_cbor, payload_cbor);
    assert(!(*signature0).empty());
    fmt::print("Signature0: {}\n", signature0);

    auto signature1 = s.sign(header_cbor, payload_cbor);
    fmt::print("Signature1: {}\n", signature1);

    // Prepare data to sign
    std::vector<uint8_t> data_to_sign;
    data_to_sign.reserve(header_cbor.size() + payload_cbor.size());
    data_to_sign.insert(data_to_sign.end(), header_cbor.begin(), header_cbor.end());
    data_to_sign.insert(data_to_sign.end(), payload_cbor.begin(), payload_cbor.end());

    // Sign the data
    std::vector<uint8_t> signature2 = sign_es256(data_to_sign, private_key);
    fmt::print("Signature2: {}\n", signature2);
    assert(!signature2.empty());

    auto signature3 = s.sign(header_cbor, payload_cbor);
    fmt::print("Signature3: {}\n", signature3);

    signer s2(private_key);
    auto   signature4 = s2.sign(header_cbor, payload_cbor);
    fmt::print("Signature4: {}\n", signature4);
    signature4 = s2.sign(header_cbor, payload_cbor);

    json                 cwt_json = json::array({header_cbor, payload_cbor, signature2});
    std::vector<uint8_t> cwt      = json::to_cbor(cwt_json);

    try {
        auto result0 = v.verify(*signature0, header_cbor, payload_cbor);
        fmt::print("Signature verification result: {}\n", result0);

        auto result1 = v.verify(*signature1, header_cbor, payload_cbor);
        fmt::print("Signature verification result: {}\n", result1);

        auto result2 = v.verify(signature2, header_cbor, payload_cbor);
        fmt::print("Signature verification result: {}\n", result2);

        auto result3 = v.verify(*signature3, header_cbor, payload_cbor);
        fmt::print("Signature verification result: {}\n", result3);

        auto result4 = v.verify(*signature4, header_cbor, payload_cbor);
        fmt::print("Signature verification result: {}\n", result4);

        json decoded_payload = verify_and_decode_cwt(cwt, std::string_view(public_key));
        std::cout << "Decoded payload: " << decoded_payload.dump(2) << std::endl;
    } catch (const std::exception &e) { std::cerr << "Error: " << e.what() << std::endl; }

    test_brute_force_attack();

    return 0;
}

auto verify_and_decode_cwt(const std::vector<uint8_t> &cwt, std::string_view public_key) -> json {
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
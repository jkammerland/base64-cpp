#include "../include/cwt.h"

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

std::vector<uint8_t> sign_es256(const std::vector<uint8_t> &data, const std::string &private_key) {
    std::vector<uint8_t> signature;
    EVP_PKEY            *pkey   = nullptr;
    EVP_MD_CTX          *md_ctx = nullptr;

    do {
        // Create a new EVP_PKEY structure
        pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_EC, nullptr, reinterpret_cast<const unsigned char *>(private_key.data()),
                                            private_key.size());
        if (!pkey)
            break;

        // Create message digest context
        md_ctx = EVP_MD_CTX_new();
        if (!md_ctx)
            break;

        // Initialize the message digest context
        if (EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0)
            break;

        // Determine the size of the signature
        size_t sig_len;
        if (EVP_DigestSign(md_ctx, nullptr, &sig_len, data.data(), data.size()) <= 0)
            break;

        // Allocate memory for the signature
        signature.resize(sig_len);

        // Create the signature
        if (EVP_DigestSign(md_ctx, signature.data(), &sig_len, data.data(), data.size()) <= 0)
            break;

        // Resize the signature to the actual size
        signature.resize(sig_len);
    } while (false);

    // Clean up
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    return signature;
}

bool verify_es256_signature(const std::vector<uint8_t> &data, const std::vector<uint8_t> &signature,
                            std::basic_string_view<unsigned char> public_key) {
    bool          result = false;
    EVP_PKEY     *pkey   = nullptr;
    EVP_PKEY_CTX *ctx    = nullptr;
    EVP_MD_CTX   *md_ctx = nullptr;

    do {
        // Create a new EVP_PKEY structure
        pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_EC, nullptr, public_key.data(), public_key.size());
        if (!pkey)
            break;

        // Create a new context for the verification operation
        ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx)
            break;

        // Initialize the verification operation
        if (EVP_PKEY_verify_init(ctx) <= 0)
            break;

        // Set the digest algorithm to SHA256
        if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
            break;

        // Create message digest context
        md_ctx = EVP_MD_CTX_new();
        if (!md_ctx)
            break;

        // Initialize the message digest context
        if (EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0)
            break;

        // Verify the signature
        int verify_result = EVP_DigestVerify(md_ctx, signature.data(), signature.size(), data.data(), data.size());

        result = (verify_result == 1);
    } while (0);

    // Clean up
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return result;
}

json verify_and_decode_cwt(const std::vector<uint8_t> &cwt, std::basic_string_view<unsigned char> public_key) {
    // Parse CWT
    json cwt_json = json::from_cbor(cwt);

    if (!cwt_json.is_array() || cwt_json.size() != 3) {
        throw std::runtime_error("Invalid CWT format");
    }

    // Extract components
    std::vector<uint8_t> header_cbor  = cwt_json[0].get<std::vector<uint8_t>>();
    std::vector<uint8_t> payload_cbor = cwt_json[1].get<std::vector<uint8_t>>();
    std::vector<uint8_t> signature    = cwt_json[2].get<std::vector<uint8_t>>();

    json header  = json::from_cbor(header_cbor);
    json payload = json::from_cbor(payload_cbor);

    // Prepare data to verify
    std::vector<uint8_t> data_to_verify;
    data_to_verify.insert(data_to_verify.end(), header_cbor.begin(), header_cbor.end());
    data_to_verify.insert(data_to_verify.end(), payload_cbor.begin(), payload_cbor.end());

    // Verify signature
    if (!verify_es256_signature(data_to_verify, signature, public_key)) {
        throw std::runtime_error("Signature verification failed");
    }

    return payload;
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    auto [private_key, public_key] = generate_es256_key_pair();

    // Create a sample CWT
    json header  = {{"alg", "ES256"}};
    json payload = {{"iss", "auth0"}, {"sub", "1234567890"}, {"aud", "client_id"}};

    std::vector<uint8_t> header_cbor  = json::to_cbor(header);
    std::vector<uint8_t> payload_cbor = json::to_cbor(payload);

    // Prepare data to sign
    std::vector<uint8_t> data_to_sign;
    data_to_sign.insert(data_to_sign.end(), header_cbor.begin(), header_cbor.end());
    data_to_sign.insert(data_to_sign.end(), payload_cbor.begin(), payload_cbor.end());

    // Sign the data
    std::vector<uint8_t> signature = sign_es256(data_to_sign, private_key);

    json                 cwt_json = json::array({header_cbor, payload_cbor, signature});
    std::vector<uint8_t> cwt      = json::to_cbor(cwt_json);

    fmt::print("Public key:\n{}\n", public_key);
    fmt::print("Private key:\n{}\n", private_key);

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
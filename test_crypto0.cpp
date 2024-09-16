#include <iostream>
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ECDSAVerifier.h" // Assuming this is the header file containing the ECDSAVerifier class
#include "ECSignature.h"   // Assuming this is the header file containing the ECDSASignature class

#include <doctest/doctest.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

// Helper function to print OpenSSL errors
void print_openssl_errors() {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char err_msg[256];
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        std::cerr << "OpenSSL Error: " << err_msg << std::endl;
    }
}

TEST_CASE("ECDSASignature encode and decode") {
    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();
    BN_set_word(r, 123456);
    BN_set_word(s, 789012);

    size_t field_size = 32; // Example field size

    SUBCASE("Encode and decode") {
        auto signature = ECDSASignature::encode(r, s, field_size);
        REQUIRE(signature.size() == 2 * field_size);

        auto [decoded_r, decoded_s] = ECDSASignature::decode(signature, field_size);
        REQUIRE(BN_cmp(r, decoded_r) == 0);
        REQUIRE(BN_cmp(s, decoded_s) == 0);

        BN_free(decoded_r);
        BN_free(decoded_s);
    }

    SUBCASE("Invalid decode") {
        std::vector<unsigned char> invalid_signature(2 * field_size - 1, 0);
        REQUIRE_THROWS_AS(ECDSASignature::decode(invalid_signature, field_size), std::invalid_argument);
    }

    BN_free(r);
    BN_free(s);
}

TEST_CASE("ECDSASignature fromECDSA_SIG and toECDSA_SIG") {
    ECDSA_SIG *sig = ECDSA_SIG_new();
    BIGNUM    *r   = BN_new();
    BIGNUM    *s   = BN_new();
    BN_set_word(r, 123456);
    BN_set_word(s, 789012);
    ECDSA_SIG_set0(sig, r, s);

    size_t field_size = 32; // Example field size

    SUBCASE("fromECDSA_SIG and toECDSA_SIG") {
        auto rs_signature = ECDSASignature::fromECDSA_SIG(sig, field_size);
        REQUIRE(rs_signature.size() == 2 * field_size);

        ECDSA_SIG *recovered_sig = ECDSASignature::toECDSA_SIG(rs_signature, field_size);
        REQUIRE(recovered_sig != nullptr);

        const BIGNUM *recovered_r, *recovered_s;
        ECDSA_SIG_get0(recovered_sig, &recovered_r, &recovered_s);
        REQUIRE(BN_cmp(r, recovered_r) == 0);
        REQUIRE(BN_cmp(s, recovered_s) == 0);

        ECDSA_SIG_free(recovered_sig);
    }

    ECDSA_SIG_free(sig);
}

TEST_CASE("ECDSASignature getFieldSize") {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    REQUIRE(key != nullptr);

    size_t field_size = ECDSASignature::getFieldSize(key);
    REQUIRE(field_size == 32); // For P-256 curve, field size should be 32 bytes

    EC_KEY_free(key);
}

TEST_CASE("ECDSASignature full cycle") {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    REQUIRE(key != nullptr);

    REQUIRE(EC_KEY_generate_key(key) == 1);

    unsigned char digest[32] = {0}; // Example digest
    ECDSA_SIG    *sig        = ECDSA_do_sign(digest, sizeof(digest), key);
    REQUIRE(sig != nullptr);

    size_t field_size = ECDSASignature::getFieldSize(key);

    SUBCASE("Full cycle conversion") {
        auto rs_signature = ECDSASignature::fromECDSA_SIG(sig, field_size);
        REQUIRE(rs_signature.size() == 2 * field_size);

        ECDSA_SIG *recovered_sig = ECDSASignature::toECDSA_SIG(rs_signature, field_size);
        REQUIRE(recovered_sig != nullptr);

        int verify_result = ECDSA_do_verify(digest, sizeof(digest), recovered_sig, key);
        REQUIRE(verify_result == 1);

        ECDSA_SIG_free(recovered_sig);
    }

    ECDSA_SIG_free(sig);
    EC_KEY_free(key);
}

TEST_CASE("ECDSASignature EVP verification") {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    REQUIRE(key != nullptr);

    REQUIRE(EC_KEY_generate_key(key) == 1);

    // Example digest and signature
    unsigned char digest[32] = {0}; // Example digest
    ECDSA_SIG    *sig        = ECDSA_do_sign(digest, sizeof(digest), key);
    REQUIRE(sig != nullptr);

    size_t field_size = ECDSASignature::getFieldSize(key);

    // Convert r|s signature to byte string
    auto rs_signature = ECDSASignature::fromECDSA_SIG(sig, field_size);
    REQUIRE(rs_signature.size() == 2 * field_size);

    // Convert EC_KEY to EVP_PKEY
    EVP_PKEY *pkey = EVP_PKEY_new();
    REQUIRE(pkey != nullptr);
    REQUIRE(EVP_PKEY_set1_EC_KEY(pkey, key) == 1);

    SUBCASE("EVP verification") {
        CHECK(rs_signature.size() == 2 * field_size);
        bool verified = ECDSAVerifier::verify(pkey, digest, sizeof(digest), rs_signature);
        CHECK(verified);
    }

    // Clean up
    EVP_PKEY_free(pkey);
    ECDSA_SIG_free(sig);
    EC_KEY_free(key);
}
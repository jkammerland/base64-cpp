#pragma once

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <stdexcept>
#include <vector>

class ECDSASignature {
  public:
    // Encode r and s into a single byte string
    static std::vector<unsigned char> encode(const BIGNUM *r, const BIGNUM *s, size_t field_size) {
        std::vector<unsigned char> signature(2 * field_size, 0);

        if (BN_bn2binpad(r, signature.data(), field_size) <= 0) {
            throw std::runtime_error("Failed to encode r");
        }
        if (BN_bn2binpad(s, signature.data() + field_size, field_size) <= 0) {
            throw std::runtime_error("Failed to encode s");
        }

        return signature;
    }

    // Decode a byte string into r and s
    static std::pair<BIGNUM *, BIGNUM *> decode(const std::vector<unsigned char> &signature, size_t field_size) {
        if (signature.size() != 2 * field_size) {
            throw std::invalid_argument("Invalid signature length");
        }

        BIGNUM *r = BN_bin2bn(signature.data(), field_size, nullptr);
        BIGNUM *s = BN_bin2bn(signature.data() + field_size, field_size, nullptr);

        if (!r || !s) {
            BN_free(r);
            BN_free(s);
            throw std::runtime_error("Failed to decode signature");
        }

        return {r, s};
    }

    // Convert OpenSSL ECDSA_SIG to r|s format
    static std::vector<unsigned char> fromECDSA_SIG(const ECDSA_SIG *sig, size_t field_size) {
        const BIGNUM *r, *s;
        ECDSA_SIG_get0(sig, &r, &s);
        return encode(r, s, field_size);
    }

    // Convert r|s format to OpenSSL ECDSA_SIG
    static ECDSA_SIG *toECDSA_SIG(const std::vector<unsigned char> &signature, size_t field_size) {
        auto [r, s]    = decode(signature, field_size);
        ECDSA_SIG *sig = ECDSA_SIG_new();
        if (!sig) {
            BN_free(r);
            BN_free(s);
            throw std::runtime_error("Failed to create ECDSA_SIG");
        }
        if (ECDSA_SIG_set0(sig, r, s) != 1) {
            ECDSA_SIG_free(sig);
            BN_free(r);
            BN_free(s);
            throw std::runtime_error("Failed to set r and s in ECDSA_SIG");
        }
        return sig;
    }

    // Helper function to get field size from EC_KEY
    static size_t getFieldSize(const EC_KEY *key) { return (EC_GROUP_get_degree(EC_KEY_get0_group(key)) + 7) / 8; }
};
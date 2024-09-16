#pragma once

#include "ECSignature.h"

#include <memory>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>

struct OSSLFREE {
    void operator()(void *p) { OPENSSL_free(p); }
};

class ECDSAVerifier {
  public:
    static bool verify(EVP_PKEY *pkey, const unsigned char *digest, size_t digest_len, const std::vector<unsigned char> &rs_signature) {
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_MD_CTX");
        }

        bool result = false;
        try {
            // Initialize the verification operation
            if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey) != 1) {
                throw std::runtime_error(getOpenSSLError());
            }

            // Convert r|s signature to DER format
            size_t                                                field_size = (EVP_PKEY_bits(pkey) + 7) / 8;
            std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(ECDSASignature::toECDSA_SIG(rs_signature, field_size),
                                                                      ECDSA_SIG_free);

            unsigned char *der_sig     = nullptr;
            int            der_sig_len = i2d_ECDSA_SIG(sig.get(), &der_sig);
            if (der_sig_len <= 0) {
                throw std::runtime_error("Failed to convert signature to DER: " + getOpenSSLError());
            }

            std::unique_ptr<unsigned char, OSSLFREE> der_sig_guard(der_sig, OSSLFREE());

            // Perform the verification
            result = (EVP_DigestVerify(ctx.get(), der_sig, der_sig_len, digest, digest_len) == 1);
        } catch (...) { throw std::runtime_error("Error during verification: " + getOpenSSLError()); }

        return result;
    }

  private:
    static std::string getOpenSSLError() {
        BIO *bio = BIO_new(BIO_s_mem());
        ERR_print_errors(bio);
        char       *buf;
        size_t      len = BIO_get_mem_data(bio, &buf);
        std::string ret(buf, len);
        BIO_free(bio);
        return ret;
    }
};
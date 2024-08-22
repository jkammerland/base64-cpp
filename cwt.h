#include <memory>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string>
#include <utility>

std::pair<std::string, std::string> generate_es256_key_pair() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();

    // Create a context for the key generation
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);

    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    // Initialize the context for key generation
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        throw std::runtime_error("Failed to initialize key generation");
    }

    // Set the elliptic curve to P-256
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) <= 0) {
        throw std::runtime_error("Failed to set curve");
    }

    // Generate the key pair
    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0) {
        throw std::runtime_error("Failed to generate key pair");
    }

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(pkey, EVP_PKEY_free);

    // Convert private key to PEM format
    std::unique_ptr<BIO, decltype(&BIO_free)> private_bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!PEM_write_bio_PrivateKey(private_bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr)) {
        throw std::runtime_error("Failed to write private key to PEM");
    }

    // Convert public key to PEM format
    std::unique_ptr<BIO, decltype(&BIO_free)> public_bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!PEM_write_bio_PUBKEY(public_bio.get(), key.get())) {
        throw std::runtime_error("Failed to write public key to PEM");
    }

    // Extract the PEM-encoded keys as strings
    char       *private_key_data   = nullptr;
    long        private_key_length = BIO_get_mem_data(private_bio.get(), &private_key_data);
    std::string private_key(private_key_data, private_key_length);

    char       *public_key_data   = nullptr;
    long        public_key_length = BIO_get_mem_data(public_bio.get(), &public_key_data);
    std::string public_key(public_key_data, public_key_length);

    // Clean up OpenSSL
    EVP_cleanup();

    return std::make_pair(private_key, public_key);
}
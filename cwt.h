#include <memory>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string>
#include <utility>
#include <vector>

std::pair<std::string, std::string> generate_es256_key_pair() {
  // Initialize OpenSSL
  OpenSSL_add_all_algorithms();

  // Create a context for the key generation
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
      EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);

  if (!ctx) {
    throw std::runtime_error("Failed to create EVP_PKEY_CTX");
  }

  // Initialize the context for key generation
  if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
    throw std::runtime_error("Failed to initialize key generation");
  }

  // Set the elliptic curve to P-256
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) <=
      0) {
    throw std::runtime_error("Failed to set curve");
  }

  // Generate the key pair
  EVP_PKEY *pkey = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0) {
    throw std::runtime_error("Failed to generate key pair");
  }

  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(pkey, EVP_PKEY_free);

  // Convert private key to PEM format
  std::unique_ptr<BIO, decltype(&BIO_free)> private_bio(BIO_new(BIO_s_mem()),
                                                        BIO_free);
  if (!PEM_write_bio_PrivateKey(private_bio.get(), key.get(), nullptr, nullptr,
                                0, nullptr, nullptr)) {
    throw std::runtime_error("Failed to write private key to PEM");
  }

  // Convert public key to PEM format
  std::unique_ptr<BIO, decltype(&BIO_free)> public_bio(BIO_new(BIO_s_mem()),
                                                       BIO_free);
  if (!PEM_write_bio_PUBKEY(public_bio.get(), key.get())) {
    throw std::runtime_error("Failed to write public key to PEM");
  }

  // Extract the PEM-encoded keys as strings
  char *private_key_data = nullptr;
  long private_key_length =
      BIO_get_mem_data(private_bio.get(), &private_key_data);
  std::string private_key(private_key_data, private_key_length);

  char *public_key_data = nullptr;
  long public_key_length = BIO_get_mem_data(public_bio.get(), &public_key_data);
  std::string public_key(public_key_data, public_key_length);

  // Clean up OpenSSL
  EVP_cleanup();

  return std::make_pair(private_key, public_key);
}

std::vector<uint8_t> sign_es256(const std::vector<uint8_t> &data,
                                const std::string &private_key) {
  std::vector<uint8_t> signature;
  EVP_PKEY *pkey = nullptr;
  EVP_MD_CTX *md_ctx = nullptr;

  try {
    // Load the private key from the string
    BIO *bio = BIO_new_mem_buf(private_key.c_str(), -1);
    if (!bio) {
      throw std::runtime_error("Failed to create BIO");
    }
    pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) {
      throw std::runtime_error("Failed to load private key");
    }

    // Create the Message Digest Context
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
      throw std::runtime_error("Failed to create Message Digest Context");
    }

    // Initialize the DigestSign operation
    if (EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
      throw std::runtime_error("Failed to initialize DigestSign operation");
    }

    // Call update with the message
    if (EVP_DigestSignUpdate(md_ctx, data.data(), data.size()) != 1) {
      throw std::runtime_error("Failed to update DigestSign");
    }

    // First, call EVP_DigestSignFinal with a NULL sig parameter to get the
    // length of the signature
    size_t sig_len;
    if (EVP_DigestSignFinal(md_ctx, nullptr, &sig_len) != 1) {
      throw std::runtime_error("Failed to get signature length");
    }

    // Resize the signature vector to the required size
    signature.resize(sig_len);

    // Now, get the actual signature
    if (EVP_DigestSignFinal(md_ctx, signature.data(), &sig_len) != 1) {
      throw std::runtime_error("Failed to create signature");
    }

    // Resize the vector to the actual signature size (it might be smaller than
    // initially allocated)
    signature.resize(sig_len);

  } catch (const std::exception &e) {
    if (pkey)
      EVP_PKEY_free(pkey);
    if (md_ctx)
      EVP_MD_CTX_free(md_ctx);
    throw; // Re-throw the exception
  }

  // Clean up
  EVP_PKEY_free(pkey);
  EVP_MD_CTX_free(md_ctx);

  return signature;
}

bool verify_es256(const std::vector<uint8_t> &data,
                  const std::vector<uint8_t> &signature,
                  std::basic_string_view<unsigned char> public_key) {
  EVP_PKEY *pkey = nullptr;
  EVP_MD_CTX *md_ctx = nullptr;
  bool signature_valid = false;

  try {
    // Load the public key from the string
    BIO *bio = BIO_new_mem_buf(public_key.data(), -1);
    if (!bio) {
      throw std::runtime_error("Failed to create BIO");
    }
    pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) {
      throw std::runtime_error("Failed to load public key");
    }

    // Create the Message Digest Context
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
      throw std::runtime_error("Failed to create Message Digest Context");
    }

    // Initialize the DigestVerify operation
    if (EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) !=
        1) {
      throw std::runtime_error("Failed to initialize DigestVerify operation");
    }

    // Call update with the message
    if (EVP_DigestVerifyUpdate(md_ctx, data.data(), data.size()) != 1) {
      throw std::runtime_error("Failed to update DigestVerify");
    }

    // Verify the signature
    int verify_result =
        EVP_DigestVerifyFinal(md_ctx, signature.data(), signature.size());
    if (verify_result == 1) {
      signature_valid = true;
    } else if (verify_result == 0) {
      signature_valid = false;
    } else {
      throw std::runtime_error("Error occurred during signature verification");
    }

  } catch (const std::exception &e) {
    if (pkey)
      EVP_PKEY_free(pkey);
    if (md_ctx)
      EVP_MD_CTX_free(md_ctx);
    throw; // Re-throw the exception
  }

  // Clean up
  EVP_PKEY_free(pkey);
  EVP_MD_CTX_free(md_ctx);

  return signature_valid;
}
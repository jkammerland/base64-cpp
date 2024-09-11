#pragma once
#include <array>
#include <initializer_list>
#include <memory>
#include <openssl/evp.h>
#include <string_view>

namespace X {

struct sha256 : std::array<unsigned char, 32u> {
    // Inherit constructors from std::array
    using std::array<unsigned char, 32u>::array;
    using std::array<unsigned char, 32u>::operator=;

    // Custom constructor to initialize from an initializer list
    sha256(std::initializer_list<unsigned char> il) { std::copy(il.begin(), il.end(), this->begin()); }

    // Implicit conversion operator to std::string_view
    operator std::string_view() const { return {reinterpret_cast<const char *>(this->data()), this->size()}; }
};

template <typename T> sha256 make_sha256(std::basic_string_view<T> data) {
    sha256      hash;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size() * sizeof(T));
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, hash.data(), &len);
    EVP_MD_CTX_free(ctx);
    return hash;
}

class sha256_stream {
  private:
    struct EVP_MD_CTX_Deleter {
        void operator()(EVP_MD_CTX *ctx) const { EVP_MD_CTX_free(ctx); }
    };

    std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> ctx;

  public:
    sha256_stream() : ctx(EVP_MD_CTX_new()) { EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr); }

    void update(std::string_view data) { EVP_DigestUpdate(ctx.get(), reinterpret_cast<const uint8_t *>(data.data()), data.size()); }

    template <typename... T> void update(T &&...data) { (update(std::forward<T>(data)), ...); }

    template <typename... T> sha256 finalize(T &&...data) {
        update(std::forward<T>(data)...);
        return finalize();
    }

    sha256 finalize() {
        sha256       hash;
        unsigned int len = 0;
        EVP_DigestFinal_ex(ctx.get(), hash.data(), &len);

        // Reinitialize the context for potential reuse
        EVP_DigestInit_ex2(ctx.get(), EVP_sha256(), nullptr);

        return hash;
    }
};

} // namespace X
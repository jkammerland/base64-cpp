#include "base64.h"
#include "sha256.h" // Replace with the actual header file name

#include <gtest/gtest.h>
#include <string>
#include <string_view>

namespace {

using namespace std::string_view_literals;

TEST(Sha256Test, DefaultConstruction) {
    X::sha256 hash;
    EXPECT_EQ(hash.size(), 32);
    for (auto byte : hash) {
        EXPECT_EQ(byte, 0);
    }
}

TEST(Sha256Test, InitializerListConstruction) {
    X::sha256 hash = {0x01, 0x02, 0x03};
    EXPECT_EQ(hash[0], 0x01);
    EXPECT_EQ(hash[1], 0x02);
    EXPECT_EQ(hash[2], 0x03);
    for (size_t i = 3; i < hash.size(); ++i) {
        EXPECT_EQ(hash[i], 0);
    }
}

TEST(Sha256Test, StringViewConversion) {
    X::sha256        hash = {0x01, 0x02, 0x03};
    std::string_view view = hash;
    EXPECT_EQ(view.size(), 32);
    EXPECT_EQ(view[0], 0x01);
    EXPECT_EQ(view[1], 0x02);
    EXPECT_EQ(view[2], 0x03);
}

TEST(Sha256Test, MakeSha256) {
    auto      input = "Hello, World!"sv;
    X::sha256 hash  = X::make_sha256(input);
    EXPECT_EQ(hash.size(), 32);
    // You might want to add a known hash value for comparison
    EXPECT_EQ("3/1gIbsr1bCvZ2KQgJ7DpTGR3YHH9wpLKGiKNiGCmG8="sv, make_sha_view(base64_encode(hash)));
}

TEST(Sha256StreamTest, BasicUsage) {
    X::sha256_stream stream;
    std::string_view input1 = "Hello, "sv;
    std::string_view input2 = "World!"sv;

    stream.update(input1);
    stream.update(input2);
    X::sha256 hash = stream.finalize();

    EXPECT_EQ(hash.size(), 32);
    // Compare with a known hash value for "Hello, World!"
}

TEST(Sha256StreamTest, MultipleUpdates) {
    X::sha256_stream stream;
    stream.update("Hello, "sv, "World!"sv, "OpenSSL"sv);
    X::sha256 hash = stream.finalize();
    EXPECT_EQ(hash.size(), 32);
    // Compare with a known hash value for "Hello, World!OpenSSL"
    EXPECT_EQ("Gy3jPDw12EW9Yph8W39cxMXbuU9NfpRsVww09G5oBio="sv, make_sha_view(base64_encode(hash)));
}

TEST(Sha256StreamTest, FinalizeWithData) {
    X::sha256_stream stream;
    X::sha256        hash = stream.finalize("Hello, "sv, "World!"sv);
    EXPECT_EQ(hash.size(), 32);
    // Compare with a known hash value for "Hello, World!"
}

TEST(Sha256StreamTest, Reuse) {
    X::sha256_stream stream;
    X::sha256        hash1 = stream.finalize("Test1"sv);
    X::sha256        hash2 = stream.finalize("Test2"sv);
    EXPECT_NE(hash1, hash2);
}

} // namespace

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
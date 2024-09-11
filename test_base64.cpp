#include "base64.h"

#include <array>
#include <cstring>
#include <gtest/gtest.h>
#include <stdexcept>
#include <string>

TEST(Base64Test, EncodeStringView) {
    EXPECT_EQ(base64_encode(""), "");
    EXPECT_EQ(base64_encode("f"), "Zg==");
    EXPECT_EQ(base64_encode("fo"), "Zm8=");
    EXPECT_EQ(base64_encode("foo"), "Zm9v");
    EXPECT_EQ(base64_encode("foob"), "Zm9vYg==");
    EXPECT_EQ(base64_encode("fooba"), "Zm9vYmE=");
    EXPECT_EQ(base64_encode("foobar"), "Zm9vYmFy");
}

TEST(Base64Test, EncodeArray) {
    std::array<unsigned char, 32> input = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                           0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

    std::array<unsigned char, 44> expected = {'A', 'A', 'E', 'C', 'A', 'w', 'Q', 'F', 'B', 'g', 'c', 'I', 'C', 'Q', 'o',
                                              'L', 'D', 'A', '0', 'O', 'D', 'x', 'A', 'R', 'E', 'h', 'M', 'U', 'F', 'R',
                                              'Y', 'X', 'G', 'B', 'k', 'a', 'G', 'x', 'w', 'd', 'H', 'h', '8', '='};

    EXPECT_EQ(base64_encode(input), expected);
}

TEST(Base64Test, DecodeStringView) {
    EXPECT_EQ(base64_decode(""), "");
    EXPECT_EQ(base64_decode("Zg=="), "f");
    EXPECT_EQ(base64_decode("Zm8="), "fo");
    EXPECT_EQ(base64_decode("Zm9v"), "foo");
    EXPECT_EQ(base64_decode("Zm9vYg=="), "foob");
    EXPECT_EQ(base64_decode("Zm9vYmE="), "fooba");
    EXPECT_EQ(base64_decode("Zm9vYmFy"), "foobar");
}

TEST(Base64Test, DecodeArray) {
    std::array<unsigned char, 44> input = {'A', 'A', 'E', 'C', 'A', 'w', 'Q', 'F', 'B', 'g', 'c', 'I', 'C', 'Q', 'o',
                                           'L', 'D', 'A', '0', 'O', 'D', 'x', 'A', 'R', 'E', 'h', 'M', 'U', 'F', 'R',
                                           'Y', 'X', 'G', 'B', 'k', 'a', 'G', 'x', 'w', 'd', 'H', 'h', '8', '='};

    std::array<unsigned char, 33> expected = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                                              0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                              0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x00};

    EXPECT_EQ(base64_decode(input), expected);
}

TEST(Base64Test, MakeShaView) {
    std::array<unsigned char, 32> input = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                           0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

    std::string_view result = make_sha_view(input);
    EXPECT_EQ(result.size(), 32);
    EXPECT_EQ(std::memcmp(result.data(), input.data(), 32), 0);
}

TEST(Base64Test, CornerCases) {
    EXPECT_EQ(base64_encode(""), "");
    EXPECT_EQ(base64_encode("f"), "Zg==");
    EXPECT_EQ(base64_decode(""), "");
    EXPECT_EQ(base64_decode("Zg=="), "f");

    EXPECT_THROW(base64_decode("Zm8"), std::runtime_error);
    EXPECT_THROW(base64_decode("Invalid!Base64"), std::runtime_error);
}

TEST(Base64Test, RoundTripString) {
    std::vector<std::string> test_cases = {
        "", "a", "ab", "abc", "abcd", "Hello, World! This is a test of Base64 encoding and decoding.", "!@#$%^&*()_+{}|:<>?`~-=[]\\;',./",
    };

    for (const auto &original : test_cases) {
        EXPECT_EQ(base64_decode(base64_encode(original)), original);
    }

    std::string binary_data(256, '\0');
    for (int i = 0; i < 256; ++i) {
        binary_data[i] = static_cast<char>(i);
    }
    EXPECT_EQ(base64_decode(base64_encode(binary_data)), binary_data);
}

TEST(Base64Test, MassiveString) {
    std::string original(1'000'000, 'a');
    for (size_t i = 0; i < original.size(); ++i) {
        original[i] = static_cast<char>('a' + (i % 26));
    }
    EXPECT_EQ(base64_decode(base64_encode(original)), original);
}

TEST(Base64Test, RoundTripArray) {
    std::array<unsigned char, 32> original = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                                              0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                              0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

    auto encoded = base64_encode(original);
    auto decoded = base64_decode(encoded);

    auto view1 = make_sha_view(original);
    auto view2 = make_sha_view(decoded);

    EXPECT_EQ(view1, view2.substr(0, 32));
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
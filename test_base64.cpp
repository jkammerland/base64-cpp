#include "base64.h"

#include <array>
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <stdexcept>
#include <string>

TEST_CASE("base64_encode string_view") {

  CHECK(base64_encode("") == "");
  CHECK(base64_encode("f") == "Zg==");
  CHECK(base64_encode("fo") == "Zm8=");
  CHECK(base64_encode("foo") == "Zm9v");
  CHECK(base64_encode("foob") == "Zm9vYg==");
  CHECK(base64_encode("fooba") == "Zm9vYmE=");
  CHECK(base64_encode("foobar") == "Zm9vYmFy");
}

TEST_CASE("base64_encode array") {

  std::array<unsigned char, 32> input = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

  std::array<unsigned char, 44> expected = {
      'A', 'A', 'E', 'C', 'A', 'w', 'Q', 'F', 'B', 'g', 'c', 'I', 'C', 'Q', 'o',
      'L', 'D', 'A', '0', 'O', 'D', 'x', 'A', 'R', 'E', 'h', 'M', 'U', 'F', 'R',
      'Y', 'X', 'G', 'B', 'k', 'a', 'G', 'x', 'w', 'd', 'H', 'h', '8', '='};

  CHECK(base64_encode(input) == expected);
}

TEST_CASE("base64_decode string_view") {

  CHECK(base64_decode("") == "");
  CHECK(base64_decode("Zg==") == "f");
  CHECK(base64_decode("Zm8=") == "fo");
  CHECK(base64_decode("Zm9v") == "foo");
  CHECK(base64_decode("Zm9vYg==") == "foob");
  CHECK(base64_decode("Zm9vYmE=") == "fooba");
  CHECK(base64_decode("Zm9vYmFy") == "foobar");
}

TEST_CASE("base64_decode array") {

  std::array<unsigned char, 44> input = {
      'A', 'A', 'E', 'C', 'A', 'w', 'Q', 'F', 'B', 'g', 'c', 'I', 'C', 'Q', 'o',
      'L', 'D', 'A', '0', 'O', 'D', 'x', 'A', 'R', 'E', 'h', 'M', 'U', 'F', 'R',
      'Y', 'X', 'G', 'B', 'k', 'a', 'G', 'x', 'w', 'd', 'H', 'h', '8', '='};

  std::array<unsigned char, 33> expected = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x00};

  CHECK(base64_decode(input) == expected);
}

TEST_CASE("make_sha256_view") {

  std::array<unsigned char, 32> input = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

  std::string_view result = make_sha256_view(input);
  CHECK(result.size() == 32);
  CHECK(std::memcmp(result.data(), input.data(), 32) == 0);
}

TEST_CASE("Corner cases") {

  CHECK(base64_encode("") == "");

  CHECK(base64_encode("f") == "Zg==");

  CHECK(base64_decode("") == "");

  CHECK(base64_decode("Zg==") == "f");

  // Missing padding
  CHECK_THROWS_AS(base64_decode("Zm8"), std::runtime_error);

  // Test invalid input for base64_decode
  CHECK_THROWS_AS(base64_decode("Invalid!Base64"), std::runtime_error);
}

TEST_CASE("Round-trip: encode then decode string") {

  SUBCASE("Empty string") {
    std::string original = "";
    CHECK(base64_decode(base64_encode(original)) == original);
  }

  SUBCASE("Single character") {
    std::string original = "a";
    CHECK(base64_decode(base64_encode(original)) == original);
  }

  SUBCASE("Two characters") {
    std::string original = "ab";
    CHECK(base64_decode(base64_encode(original)) == original);
  }

  SUBCASE("Three characters") {
    std::string original = "abc";
    CHECK(base64_decode(base64_encode(original)) == original);
  }

  SUBCASE("Four characters") {
    std::string original = "abcd";
    CHECK(base64_decode(base64_encode(original)) == original);
  }

  SUBCASE("Longer string") {
    std::string original =
        "Hello, World! This is a test of Base64 encoding and decoding.";
    CHECK(base64_decode(base64_encode(original)) == original);
  }

  SUBCASE("String with special characters") {
    std::string original = "!@#$%^&*()_+{}|:<>?`~-=[]\\;',./";
    CHECK(base64_decode(base64_encode(original)) == original);
  }

  SUBCASE("Binary data") {
    std::string original(256, '\0');
    for (int i = 0; i < 256; ++i) {
      original[i] = static_cast<char>(i);
    }
    CHECK(base64_decode(base64_encode(original)) == original);
  }
}

TEST_CASE("Massive string") {

  std::string original(1'000'000, 'a');

  // Make alphabet soup
  for (size_t i = 0; i < original.size(); ++i) {
    original[i] = static_cast<char>('a' + (i % 26));
  }

  CHECK(base64_decode(base64_encode(original)) == original);
}

TEST_CASE("Round-trip: encode then decode array") {

  std::array<unsigned char, 32> original = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

  auto encoded = base64_encode(original);
  auto decoded = base64_decode(encoded);

  auto view1 = make_sha256_view(original);
  auto view2 = make_sha256_view(decoded);

  CHECK(view1 == view2.substr(0, 32));
}
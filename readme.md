# Cryptographic Signing and Verification Library

This library provides classes for digital signature creation and verification using the OpenSSL library. It includes two main classes: `signer` for creating signatures and `verifier` for verifying signatures.

## Features

- ES256 (ECDSA with SHA-256) signature creation and verification
- Support for CBOR-encoded data
- Easy-to-use interface for signing and verifying multiple data chunks

## Requirements

- C++17 or later
- OpenSSL library
- nlohmann/json library (for JSON and CBOR handling)

## Usage

### Signer Class

The `signer` class is used to create digital signatures.

```cpp
// Create a signer object with a private key
signer s(std::string_view(private_key));

// Sign data
std::vector<uint8_t> data1 = {...};
std::vector<uint8_t> data2 = {...};
auto signature = s.sign(data1, data2);

// Check if signature was created successfully
if (signature) {
    // Use the signature
} else {
    // Handle error
}
```

### Verifier Class

The `verifier` class is used to verify digital signatures.

```cpp
// Create a verifier object with a public key
verifier v(std::string_view(public_key));

// Verify a signature
std::vector<uint8_t> data1 = {...};
std::vector<uint8_t> data2 = {...};
std::vector<uint8_t> signature = {...};

bool is_valid = v.verify(signature, data1, data2);

if (is_valid) {
    // Signature is valid
} else {
    // Signature is invalid
}
```

## Example

The provided `test_brute_force_attack` function demonstrates how to use the `signer` and `verifier` classes:

1. Generate an ES256 key pair
2. Create a signer and verifier with the respective keys
3. Create a sample CWT (CBOR Web Token)
4. Sign the CBOR-encoded data
5. Verify the signature
6. Perform a brute-force attack simulation

## Notes

- The library uses ECDSA with SHA-256 (ES256) for signing and verification.
- Error handling is done through exceptions in the constructors and optional return values for signing operations.
- The verifier's `verify` method is marked with `[[nodiscard]]` to encourage checking the return value.
- The library supports signing and verifying multiple data chunks in a single operation.

## Security Considerations

- Ensure that private keys are kept secure and not exposed in your code.
- Use strong, randomly generated keys for production use.
#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

typedef struct {
    BIGNUM *r;
    BIGNUM *s;
} ECDSA_SIG_ST;

ASN1_SEQUENCE(ECDSA_SIG_ST) = {ASN1_SIMPLE(ECDSA_SIG_ST, r, BIGNUM), ASN1_SIMPLE(ECDSA_SIG_ST, s, BIGNUM)} ASN1_SEQUENCE_END(ECDSA_SIG_ST)
                                  DECLARE_ASN1_FUNCTIONS(ECDSA_SIG_ST) IMPLEMENT_ASN1_FUNCTIONS(ECDSA_SIG_ST)

                                      unsigned char *
                              convert_rs_to_seq(const unsigned char *rs, size_t rs_len, size_t *seq_len) {
    if (rs_len % 2 != 0) {
        return nullptr; // RS format should have even length
    }

    size_t  field_size = rs_len / 2;
    BIGNUM *r          = BN_bin2bn(rs, field_size, NULL);
    BIGNUM *s          = BN_bin2bn(rs + field_size, field_size, NULL);

    if (!r || !s) {
        BN_free(r);
        BN_free(s);
        return nullptr;
    }

    ECDSA_SIG_ST *sig = ECDSA_SIG_ST_new();
    if (!sig) {
        BN_free(r);
        BN_free(s);
        return nullptr;
    }

    sig->r = r;
    sig->s = s;

    unsigned char *seq = nullptr;
    *seq_len           = i2d_ECDSA_SIG_ST(sig, &seq);

    ECDSA_SIG_ST_free(sig); // This will also free r and s

    return seq;
}

// Example usage
void example_usage() {
    // Example RS format signature (64 bytes for P-256 curve)
    unsigned char rs[64] = {
        0x01, 0x23, 0x45, 0x67, /* ... fill with actual signature ... */
    };
    size_t rs_len = sizeof(rs);

    size_t         seq_len;
    unsigned char *seq = convert_rs_to_seq(rs, rs_len, &seq_len);

    if (seq) {
        // Use seq here...
        OPENSSL_free(seq);
    }
}

int main() {
    example_usage();
    return 0;
}
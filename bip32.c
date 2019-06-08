#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <libbase58.h>
#include "fastpbkdf2.h"

typedef union {
    uint32_t value;
    uint8_t bytes[4];
} uint32_u;

typedef struct {
    uint32_u version;
    uint8_t depth;
    uint32_u fingerprint;
    uint32_u child;
    uint8_t chaincode[32];
    uint8_t key[33];
    uint32_u checksum;
} __attribute__((packed)) serialized_hd_key_t;

typedef union {
    uint8_t packed[82];
    serialized_hd_key_t ser;
} serialized_hd_key_u;

void fprinthex_fancy_broken(FILE *f, const uint8_t *data, size_t data_sz, int width, char sep, int printascii) {
    const uint8_t *b = data, *data_end = data + data_sz;
    while (b < data_end) {
        int lnpos;
        for (lnpos = 0; lnpos < width && b + lnpos < data_end; ++lnpos) {
            if (sep) {
                fprintf(f, "%02x%c", b[lnpos], sep);
            } else {
                fprintf(f, "%02x", b[lnpos]);
            }
        }
        if (printascii) {
            fprintf(f, " | ");
            for (lnpos = 0; lnpos < width && b + lnpos < data_end; ++lnpos) {
                if (isprint(b[lnpos])) {
                    fprintf(f, "%c", b[lnpos]);
                } else {
                    fprintf(f, ".");
                }
            }
        }
        fprintf(f, "\n");
        b += lnpos;
    }
}

void fprinthex(FILE *f, const uint8_t *data, size_t data_sz) {
    for (const uint8_t *b = data; b < data + data_sz; ++b) {
        fprintf(f, "%02x", *b);
    }
    fprintf(f, "\n");
}

bool my_sha256(void *digest, const void *data, size_t datasz) {
    SHA256((const uint8_t*)data, datasz, digest);
    return 1;
}

int main(int argc, char *argv[]) {
    while (argc--) {argv++;}
    b58_sha256_impl = my_sha256;
    const char *pw = getenv("PW");
    const char *salt = getenv("SALT");
    const char seed[] = "Bitcoin seed";
    uint8_t dk[64];
    uint8_t md[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    serialized_hd_key_u binhdkey = { .ser = {
        .version = { .bytes = { 0x04, 0x88, 0xad, 0xe4 } }, // big-endian 'xprv'
        .depth = 0x00,
        .fingerprint = { .value = 0 },
        .child = { .value = 0 }
    } };
    uint8_t checksum_hash_int[32];
    uint8_t checksum_hash_final[32];
    char b58hdkey[256];
    size_t b58hdkeylen = sizeof(b58hdkey);

    fastpbkdf2_hmac_sha512((const uint8_t*)pw, strlen(pw), (const uint8_t*)salt, strlen(salt), 2048, dk, sizeof(dk));
    printf("dk: ");
    fprinthex(stdout, dk, sizeof(dk));

    HMAC(EVP_sha512(), seed, strlen(seed), dk, sizeof(dk), md, &md_len);
    printf("md: ");
    fprinthex(stdout, md, sizeof(md));
    memcpy(binhdkey.ser.chaincode, md + 32, 32);
    binhdkey.ser.key[0] = 0x00;
    memcpy(binhdkey.ser.key + 1, md, 32);

    SHA256(binhdkey.packed, sizeof(binhdkey.packed), checksum_hash_int);
    SHA256(checksum_hash_int, sizeof(checksum_hash_int), checksum_hash_final);
    memcpy(binhdkey.ser.checksum.bytes, checksum_hash_final, 4);
    printf("checksum_hash_final: ");
    fprinthex(stdout, checksum_hash_final, sizeof(checksum_hash_final));

    b58enc(b58hdkey, &b58hdkeylen, binhdkey.packed, sizeof(binhdkey.packed));
    printf("b58enc: %s\n", b58hdkey);

    return 0;
}

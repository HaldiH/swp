//
// Created by hugo on 09.12.19.
//

#include <cstdint>
#include <argon2.h>
#include <cstring>
#include <binary.hpp>

#define HASHLEN 32
#define PWD "password"

int main(void) {
    std::string pwd = "password";
    const std::string salt = "test1234";

    uint8_t hash1[HASHLEN];
    uint8_t hash2[HASHLEN];

    uint8_t *pwd2 = (uint8_t *) strdup(PWD);
    uint32_t pwd2_len = strlen((char *) pwd2);

    uint32_t t_cost = 2;            // 1-pass computation
    uint32_t m_cost = (1 << 16);      // 64 mebibytes memory usage
    uint32_t parallelism = 1;       // number of threads and lanes

    // high-level API
    argon2i_hash_raw(t_cost, m_cost, parallelism, pwd.c_str(), pwd.size(), salt.c_str(), salt.size(), hash1, HASHLEN);
    char *encoded = static_cast<char *>(malloc(256 * sizeof(char *)));
    argon2i_hash_encoded(t_cost, m_cost, parallelism, pwd.c_str(), pwd.size(), salt.c_str(), salt.size(), HASHLEN,
                         encoded, 256);
    auto b = argon2i_verify("$argon2i$v=19$m=4096,t=3,p=1$Hxlqs6i0CUEpsbhVERYQVQ$9KCkK3tjxFdyjPGPy/VMA8cb7iE4ZCcdkOkmvr9unKo", pwd.c_str(), pwd.size());

    std::cout << b << std::endl;

    // low-level API
    argon2_context context = {
            hash2,  /* output array, at least HASHLEN in size */
            HASHLEN, /* digest length */
            pwd2, /* password array */
            pwd2_len, /* password length */
            (uint8_t *) salt.c_str(),  /* salt array */
            static_cast<uint32_t>(salt.size()), /* salt length */
            NULL, 0, /* optional secret data */
            NULL, 0, /* optional associated data */
            t_cost, m_cost, parallelism, parallelism,
            ARGON2_VERSION_13, /* algorithm version */
            NULL, NULL, /* custom memory allocation / deallocation functions */
            /* by default only internal memory is cleared (pwd is not wiped) */
            ARGON2_DEFAULT_FLAGS
    };

    int rc = argon2i_ctx(&context);
    if (ARGON2_OK != rc) {
        printf("Error: %s\n", argon2_error_message(rc));
        exit(1);
    }

    pwd = {};

    for (int i = 0; i < HASHLEN; ++i) printf("%02x", hash1[i]);
    printf("\n");
    if (memcmp(hash1, hash2, HASHLEN)) {
        for (int i = 0; i < HASHLEN; ++i) {
            printf("%02x", hash2[i]);
        }
        printf("\nfail\n");
    } else printf("ok\n");
    return 0;
}
#ifndef AES256CTR_HPP
#define AES256CTR_HPP

#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>
#include <utility>
#include<stdbool.h>

typedef unsigned char byte;

class AES256CTR {
public:
    AES256CTR(byte* key, byte* iv);

    std::pair<std::pair<const byte*, size_t>, const char*> encrypt(const byte* plaintext, size_t length, bool debug = false);

    std::pair<std::pair<const byte*, size_t>, const char*> decrypt(const byte* ciphertext, size_t length, bool debug = false);

    ~AES256CTR();

private:
    byte* key_;
    byte* iv_;
    byte* ctx;

    inline void free();
};

#endif
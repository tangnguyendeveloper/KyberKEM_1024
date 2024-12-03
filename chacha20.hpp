#ifndef CHACHA20_HPP
#define CHACHA20_HPP

#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>
#include <utility>
#include <stdbool.h>

typedef unsigned char byte;

class ChaCha20 {
public:
    // ChaCha20 uses a 32-byte key and 12-byte nonce
    ChaCha20(byte* key, byte* nonce);
    
    std::pair<std::pair<const byte*, size_t>, const char*> encrypt(const byte* plaintext, size_t length, bool debug = false);
    std::pair<std::pair<const byte*, size_t>, const char*> decrypt(const byte* ciphertext, size_t length, bool debug = false);
    
    ~ChaCha20();

private:
    byte* key_;
    byte* nonce_;
    byte* ctx;

    inline void free();
};

#endif
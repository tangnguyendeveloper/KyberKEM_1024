#include "chacha20.hpp"
#include <stdexcept>

ChaCha20::ChaCha20(byte* key, byte* nonce) {
    this->ctx = nullptr;
    this->key_ = key;
    this->nonce_ = nonce;
}

ChaCha20::~ChaCha20() {
    this->free();
    if (this->key_ != nullptr) delete[] this->key_;
    if (this->nonce_ != nullptr) delete[] this->nonce_;
}

void ChaCha20::free() {
    if (this->ctx != nullptr) delete[] this->ctx;
}

std::pair<std::pair<const byte*, size_t>, const char*> ChaCha20::encrypt(const byte* plaintext, size_t length, bool debug) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    
    int ret = EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, this->key_, this->nonce_);
    if (ret <= 0) {
        if (debug) ERR_print_errors_fp(stderr);
        return std::make_pair(std::make_pair(nullptr, 0), "Error initializing encryption context");
    }

    byte* ciphertext = new byte[length];
    int ciphertext_len = 0;
    ret = EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, length);
    if (ret <= 0) {
        delete[] ciphertext;
        if (debug) ERR_print_errors_fp(stderr);
        return std::make_pair(std::make_pair(nullptr, 0), "Error encrypting data");
    }

    EVP_CIPHER_CTX_free(ctx);
    this->free();
    this->ctx = ciphertext;
    return std::make_pair(std::make_pair(ciphertext, ciphertext_len), nullptr);
}

std::pair<std::pair<const byte*, size_t>, const char*> ChaCha20::decrypt(const byte* ciphertext, size_t length, bool debug) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    
    int ret = EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, this->key_, this->nonce_);
    if (ret <= 0) {
        if (debug) ERR_print_errors_fp(stderr);
        return std::make_pair(std::make_pair(nullptr, 0), "Error initializing decryption context");
    }

    byte* plaintext = new byte[length];
    int plaintext_len = 0;
    ret = EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, length);
    if (ret <= 0) {
        delete[] plaintext;
        if (debug) ERR_print_errors_fp(stderr);
        return std::make_pair(std::make_pair(nullptr, 0), "Error decrypting data");
    }

    EVP_CIPHER_CTX_free(ctx);
    this->free();
    this->ctx = plaintext;
    return std::make_pair(std::make_pair(plaintext, plaintext_len), nullptr);
}
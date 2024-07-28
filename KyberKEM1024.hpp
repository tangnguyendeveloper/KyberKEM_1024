#ifndef KYBER1024_H_
#define KYBER1024_H_


#include <random>
#include <cstring>
#include <string>
#include <sstream>
#include <utility>
#include <fstream>
#include <iomanip>
#include <algorithm>

#include "rng.h"
#include "api.h"
#include "verify.h"

typedef unsigned char byte;
typedef std::string error;


class KyberKEM {

    private:

    byte* secret_key = nullptr;
    byte* share_secret = nullptr;

    byte* GetEntropy();

    error WriteToFile(const byte* data, const size_t length , const std::string filename);
    error ReadFromFile(const std::string filename, byte* out, const size_t length);

    public:
    KyberKEM();
    KyberKEM(const KyberKEM& kyber_kem);
    ~KyberKEM();

    // filename omitting filename extension
    //  the filename extension '.pub'
    error SavePublicKey(const byte* public_key, const std::string filename);
    // filename omitting filename extension
    //  the filename extension '.pub'
    std::pair<byte*, error> LoadPublicKey(const std::string filename);

    // filename omitting filename extension
    //  the filename extension '.pem'
    error SaveSecretKey(const std::string filename);
    // filename omitting filename extension
    //  the filename extension '.pem'
    error LoadSecretKey(const std::string filename);

    // self share secret key
    byte* ShareSecret();
    

    // Return a public key and error message if error
    std::pair<byte*, error> RandomKey(byte *entropy_input, byte *personalization_string, size_t personalization_string_length);
    // Return a ciphertext and error message if error
    // The ciphertext can used to obtain the shared secret using the secret key 
    std::pair<byte*, error> KeyEncapsulation(const byte* public_key);
    // Return a shared secret and error message if error
    // Obtain the shared secret using the secret key
    std::pair<byte*, error> KeyDecapsulation(const byte* ciphertext);

    // The secret_key of two KyberKEM are same?
    bool operator==(const KyberKEM& other) const;

};


#endif /* KYBER1024_H_ */
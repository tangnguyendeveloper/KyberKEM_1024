/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rng.h"
#include "api.h"


#define KAT_SUCCESS          0
#define KAT_CRYPTO_FAILURE  -4

int main()
{
    unsigned char       seed[48];
    unsigned char       entropy_input[48];
    unsigned char       ct[CRYPTO_CIPHERTEXTBYTES], ss[CRYPTO_BYTES], ss1[CRYPTO_BYTES];
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int                 ret_val;


    for (int i=0; i<48; i++)
        entropy_input[i] = i;

    randombytes_init(entropy_input, NULL, 256);
    randombytes(seed, 48);

    printf("%s", "seed: ");
    for (int i = 0; i < 48; i++) printf("%02X", seed[i]);
    printf("\n");
    
    randombytes_init(seed, NULL, 256);

    // Generate the public/private keypair
    if ( (ret_val = crypto_kem_keypair(pk, sk)) != 0) {
        printf("crypto_kem_keypair returned <%d>\n", ret_val);
        return KAT_CRYPTO_FAILURE;
    }

    printf("%s", "public key: ");
    for (int i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) printf("%02X", pk[i]);
    printf("\n");
    printf("%s", "secret key: ");
    for (int i = 0; i < CRYPTO_SECRETKEYBYTES; i++) printf("%02X", sk[i]);
    printf("\n");

    //key encapsulation
    if ( (ret_val = crypto_kem_enc(ct, ss, pk)) != 0) {
        printf("crypto_kem_enc returned <%d>\n", ret_val);
        return KAT_CRYPTO_FAILURE;
    }

    printf("%s", "ciphertext: ");
    for (int i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) printf("%02X", ct[i]);
    printf("\n");
    printf("%s", "share secret: ");
    for (int i = 0; i < CRYPTO_BYTES; i++) printf("%02X", ss[i]);
    printf("\n");


    // Decrypt key from ciphertext
    if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) {
        printf("crypto_kem_dec returned <%d>\n", ret_val);
        return KAT_CRYPTO_FAILURE;
    }

    printf("%s", "share secret from ciphertext: ");
    for (int i = 0; i < CRYPTO_BYTES; i++) printf("%02X", ss1[i]);
    printf("\n");

    if ( memcmp(ss, ss1, CRYPTO_BYTES) ) {
        printf("crypto_kem_dec returned bad 'ss' value\n");
        return KAT_CRYPTO_FAILURE;
    }

    return KAT_SUCCESS;
}
*/

#include "KyberKEM1024.hpp"
#include <iostream>
#include <chrono>
#include "verify.h"



int main(){

    KyberKEM user1, user2;

    // Random key
    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::pair<byte*, error> result = user1.RandomKey();
    if (!result.first) {
        std::cerr << result.second << std::endl;
        return 0;
    }
    byte* public_key_u1 = result.first;

    result = user2.RandomKey();
    if (!result.first) {
        std::cerr << result.second << std::endl;
        return 0;
    }
    byte* public_key_u2 = result.first;

    auto end_time = std::chrono::high_resolution_clock::now();
    auto elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    std::cout << "Gennerate key: " << elapsed_time.count() << " microseconds\n";
    
    // Save key
    if (error err = user1.SaveSecretKey("user1"); err != "") std::cerr << err << std::endl;
    if (error err = user2.SaveSecretKey("user2"); err != "") std::cerr << err << std::endl;

    if (error err = user1.SavePublicKey(public_key_u1, "user1"); err != "") std::cerr << err << std::endl;
    if (error err = user2.SavePublicKey(public_key_u2, "user2"); err != "") std::cerr << err << std::endl;

    
    // Load key
    if (error err = user1.LoadSecretKey("user1");  err != "") std::cerr << err << std::endl;
    if (error err = user2.LoadSecretKey("user2");  err != "") std::cerr << err << std::endl;

    result = user1.LoadPublicKey("user1");
    if (!result.first) {
        std::cerr << result.second << std::endl;
        return 0;
    }
    byte* public_key_u1_1 = result.first;

    result = user2.LoadPublicKey("user2");
    if (!result.first) {
        std::cerr << result.second << std::endl;
        return 0;
    }
    byte* public_key_u2_1 = result.first;

   if (
        !verify(public_key_u1, public_key_u1_1, CRYPTO_PUBLICKEYBYTES)
        && !verify(public_key_u2, public_key_u2_1, CRYPTO_PUBLICKEYBYTES)
    ) std::cout << "Load Key OK!\n";
    else std::cerr << "Load Key ERROR!\n";


    // Key Encapsulation

    start_time = std::chrono::high_resolution_clock::now();

    result = user1.KeyEncapsulation(public_key_u2);
    if (!result.first) {
        std::cerr << result.second << std::endl;
        return 0;
    }
    byte* ciphertext_u1 = result.first;

    result = user2.KeyEncapsulation(public_key_u1);
    if (!result.first) {
        std::cerr << result.second << std::endl;
        return 0;
    }
    byte* ciphertext_u2 = result.first;


    end_time = std::chrono::high_resolution_clock::now();
    elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    std::cout << "Key encapsulation: " << elapsed_time.count() << " microseconds\n";


    // Key Decapsulation

    start_time = std::chrono::high_resolution_clock::now();

    result = user1.KeyDecapsulation(ciphertext_u2);
    if (!result.first) {
        std::cerr << result.second << std::endl;
        return 0;
    }
    byte* shared_secret_u2 = result.first;

    result = user2.KeyDecapsulation(ciphertext_u1);
    if (!result.first) {
        std::cerr << result.second << std::endl;
        return 0;
    }
    byte* shared_secret_u1 = result.first;

    end_time = std::chrono::high_resolution_clock::now();
    elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    std::cout << "Key decapsulation: " << elapsed_time.count() << " microseconds\n";

    byte* s1 = user1.ShareSecret();
    byte* s2 = user2.ShareSecret();

    if (
        !verify(s1, shared_secret_u1, CRYPTO_BYTES)
        && !verify(s2, shared_secret_u2, CRYPTO_BYTES)
    ) std::cout << "Encapsulation and Decapsulation Key OK!\n";
    else std::cerr << "Encapsulation and Decapsulation Key ERROR!\n";


    std::cout << "\nshared_secret user1: ";
    for (int i = 0; i < CRYPTO_BYTES; i++) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)shared_secret_u1[i];
    std::cout << std::endl;

    std::cout << "\nshared_secret user2: ";
    for (int i = 0; i < CRYPTO_BYTES; i++) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)shared_secret_u2[i];
    std::cout << std::endl;

    delete[] public_key_u1, public_key_u2, public_key_u1_1, public_key_u2_1;
    delete[] ciphertext_u1, ciphertext_u2;
    delete[] shared_secret_u1, shared_secret_u2;
    delete[] s1, s2;

    return 0;
}
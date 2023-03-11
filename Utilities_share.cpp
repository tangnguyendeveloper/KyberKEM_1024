#include "KyberKEM1024.hpp"


extern "C" {

    KyberKEM* NewKyberKEM() {return new KyberKEM();}
    KyberKEM* CopyKyberKEM(const KyberKEM& kyber_kem) {return new KyberKEM(kyber_kem);}

    void DeleteKyberKEM(KyberKEM* kyber_kem) {return kyber_kem->~KyberKEM();}

    error SavePublicKey(KyberKEM* kyber_kem, const byte* public_key, const std::string filename) {
        return kyber_kem->SavePublicKey(public_key, filename);
    }

    std::pair<byte*, error> LoadPublicKey(KyberKEM* kyber_kem, const std::string filename){
        return kyber_kem->LoadPublicKey(filename);
    }

    error SaveSecretKey(KyberKEM* kyber_kem, const std::string filename){
        return kyber_kem->SaveSecretKey(filename);
    }

    error LoadSecretKey(KyberKEM* kyber_kem, const std::string filename){
        return kyber_kem->LoadSecretKey(filename);
    }

    byte* ShareSecret(KyberKEM* kyber_kem) {
        return kyber_kem->ShareSecret();
    }

    void DeleteArray(byte* array) {delete[] array;}

    std::pair<byte*, error> RandomKey(KyberKEM* kyber_kem) {
        return kyber_kem->RandomKey();
    }

    std::pair<byte*, error> KeyEncapsulation(KyberKEM* kyber_kem, const byte* public_key) {
        return kyber_kem->KeyEncapsulation(public_key);
    }

    std::pair<byte*, error> KeyDecapsulation(KyberKEM* kyber_kem, const byte* ciphertext) {
        return kyber_kem->KeyDecapsulation(ciphertext);
    }

}

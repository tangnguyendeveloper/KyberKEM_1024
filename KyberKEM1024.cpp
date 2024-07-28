#include "KyberKEM1024.hpp"


KyberKEM::KyberKEM(){
    this->secret_key = new byte[CRYPTO_SECRETKEYBYTES];
    this->share_secret = new byte[CRYPTO_BYTES];
}


KyberKEM::~KyberKEM() {
    delete[] this->secret_key;
    delete[] this->share_secret;
}


KyberKEM::KyberKEM(const KyberKEM& kyber_kem) {
    if (this->secret_key == nullptr || this->share_secret == nullptr) KyberKEM();

    size_t n = static_cast<size_t>(CRYPTO_SECRETKEYBYTES);
    memcpy(this->secret_key, kyber_kem.secret_key, n);

    n = static_cast<size_t>(CRYPTO_BYTES);
    memcpy(this->share_secret, kyber_kem.share_secret, n);
}


byte* KyberKEM::GetEntropy() {
    byte* entropy = new byte[45];

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<byte> dist(0, 255);

    for (int i = 0; i < 45; i++) {
        entropy[i] = dist(gen);
    }

    return entropy;
}


std::pair<byte*, error> KyberKEM::RandomKey(byte *entropy_input, byte *personalization_string, size_t personalization_string_length) {

    byte seed[48];
    bool gennerate_entropy = !entropy_input;
    if (gennerate_entropy) entropy_input = this->GetEntropy();

    byte* public_key = new byte[CRYPTO_PUBLICKEYBYTES];
    std::ostringstream error;
    int ret_val = 0;

    randombytes_init(entropy_input, personalization_string, personalization_string_length);
    randombytes(seed, 48);

    if (gennerate_entropy) delete[] entropy_input;

    randombytes_init(seed, NULL, 0);

    if ((ret_val = crypto_kem_keypair(public_key, this->secret_key)) != 0) {
        error << "ERROR: crypto_kem_keypair returned <" << ret_val << ">";
        delete[] public_key;
        return std::make_pair(nullptr, error.str());
    }
    return std::make_pair(public_key, "");
}


std::pair<byte*, error> KyberKEM::KeyEncapsulation(const byte* public_key) {

    int ret_val = 0;
    std::ostringstream error;
    byte* ciphertext = new byte[CRYPTO_CIPHERTEXTBYTES];

    if ( (ret_val = crypto_kem_enc(ciphertext, this->share_secret, public_key)) != 0) {
        error << "ERROR: crypto_kem_enc returned <" << ret_val << ">";
        delete[] ciphertext;
        return std::make_pair(nullptr, error.str());
    }

    return std::make_pair(ciphertext, "");
}


std::pair<byte*, error> KyberKEM::KeyDecapsulation(const byte* ciphertext) {

    int ret_val = 0;
    std::ostringstream error;
    byte* share_secret_encapsulated = new byte[CRYPTO_BYTES];
    if ( (ret_val = crypto_kem_dec(share_secret_encapsulated, ciphertext, this->secret_key)) != 0) {
        error << "ERROR: crypto_kem_dec returned <" << ret_val << ">";
        delete[] share_secret_encapsulated;
        return std::make_pair(nullptr, error.str());
    }

    return std::make_pair(share_secret_encapsulated, "");
}


byte* KyberKEM::ShareSecret() {
    
    size_t n = static_cast<size_t>(CRYPTO_BYTES);
    byte* result = new byte[n];
    memcpy(result, this->share_secret, n);
    return result;

}

error KyberKEM::WriteToFile(const byte* data, const size_t length , const std::string filename){
    std::ofstream file(filename);

    if (file.is_open()) {
        for (size_t i = 0; i < length; i++)
            file << std::hex << std::setw(2) << std::setfill('0') << (int)(data[i]);
        file.close();
        return "";
    }

    return "ERROR: can't open file " + filename;
}


error KyberKEM::SaveSecretKey(const std::string filename){
    return this->WriteToFile(
        this->secret_key,
        static_cast<size_t>(CRYPTO_SECRETKEYBYTES),
        filename+".pem"
    );
}


error KyberKEM::SavePublicKey(const byte* public_key, const std::string filename){
    return this->WriteToFile(
        public_key,
        static_cast<size_t>(CRYPTO_PUBLICKEYBYTES),
        filename+".pub"
    );
}


error KyberKEM::ReadFromFile(const std::string filename, byte* out, const size_t length) {

    std::ifstream file(filename);

     if (file.is_open()) {

        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string hexString = buffer.str();

        hexString.erase(remove_if(hexString.begin(), hexString.end(), isspace), hexString.end());

        if (hexString.length() != 2 * length) return "Error: invalid hex string length";
        std::string byteString = "";
        for (size_t i = 0; i < length; i++) {
            byteString = hexString.substr(i * 2, 2);
            out[i] = (byte)strtol(byteString.c_str(), NULL, 16);
        }

        file.close();
        return "";
     }

     return "ERROR: can't open file " + filename;

}


error KyberKEM::LoadSecretKey(const std::string filename) {
    return this->ReadFromFile(
        filename + ".pem",
        this->secret_key,
        static_cast<size_t>(CRYPTO_SECRETKEYBYTES)
    );
}


std::pair<byte*, error> KyberKEM::LoadPublicKey(const std::string filename) {
    byte* public_key = new byte[CRYPTO_PUBLICKEYBYTES];

    error err = this->ReadFromFile(
        filename + ".pub", public_key, 
        static_cast<size_t>(CRYPTO_PUBLICKEYBYTES)
    );

    if (err != "") {
        delete[] public_key;
        return std::make_pair(nullptr, err);
    }

    return std::make_pair(
        public_key,
        err
    );
}

bool KyberKEM::operator==(const KyberKEM& other) const{
    return !verify(this->secret_key, other.secret_key, CRYPTO_SECRETKEYBYTES);
}
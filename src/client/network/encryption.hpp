#include <openssl/evp.h>

#include <memory>



constexpr int AES_KeyLen_bits = 256;
constexpr int AES_IVLen_bits = 128;
constexpr int AES_KeyLen_bytes = AES_KeyLen_bits/8;
constexpr int AES_IVLen_bytes = AES_IVLen_bits/8;

class Encryption
{
private:
    // For packet encryption the first 3 bytes are not encrypted.
    // 01 02 03
    // 01 - Control byte (type of packet)
    // 02 03 - Size of encrypted packet
    // These bytes are needed for the application to determine how to deal with and read the packet
    // 
    // Packet structure
    // 00-02 (control and packet size)
    // 03-35 (32 bytes) HMAC-SHA256 hash of IV and payload
    // 35-51 (16 bytes) AES-256-CBC IV
    // 52-nn (n bytes)  AES-256-CBC message payload
    //
    //    |--|------------|------|---------------------------------|
    // Ctrl+Size   HMAC      IV            AES ENC Payload
    //
    // Determined AES KEY from DH agreed key
    // The dh shared key will be 256 bytes but a hash like sha256 can be used to get our 256 bits (16 bytes) key.
    // CANNOT BE sent over network
    unsigned char key[AES_KeyLen_bytes];
    
    // Initalization vector, can be sent over the network.
    // Should have MAC code to determine integrity
    unsigned char IV[AES_IVLen_bytes];

    // Public peer
    EVP_PKEY* dhPeerKey;
    // Public and private client key
    EVP_PKEY* dhKey;

public:

    /// @brief Encrypt data to be sent over network
    /// @param data 
    /// @param plainTextLen 
    /// @param iv 
    /// @param cipherTextOut 
    /// @return Int - number of bytes of cipher text. -1 if error occured
    int EncryptData(const unsigned char& data, const size_t plainTextLen, const unsigned char& iv, std::unique_ptr<unsigned char[]>& cipherTextOut);


    /// @brief Decrypts the data recieved over the network
    /// @param cipherData 
    /// @param cipherDataLen 
    /// @param iv 
    /// @param dataOut 
    /// @return Int - number of bytes after decryption. -1 if error occured
    int DecryptData(const unsigned char& cipherData, const size_t cipherDataLen, const unsigned char& iv, std::unique_ptr<unsigned char[]>& dataOut);


    /// @brief Creates the public-private key pair for the Diffie Hellman key exchange
    /// @return Bool - success
    bool CreateDHKeys(void);


    bool GetDHPubKey(unsigned char* DHpublicKeyOut);

    /// @brief Will derive the AES secret key from both DH keys
    /// @return success
    bool DeriveSecretKey(void);


    bool CreateHMAC(const unsigned char* packetPayload, unsigned char* hmacHashOut);

    
    bool VerifyHMAC(const unsigned char* hmacHash, const unsigned char* packetPayload);


    /// @brief Create a sha256 hash from input data
    /// @param data Bytes to hash
    /// @param dataSize Number of bytes to hash
    /// @param hashOut Buffer to write the hash to
    /// @return Bool - success
    bool CalculateSHA256(const unsigned char* data, const size_t dataSize, unsigned char* hashOut);


    // Generate all relevant contexts and keys
    Encryption();
    // Free all openssl resources
    ~Encryption();
};

#include <openssl/evp.h>

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
    /// @param data Raw unencrypted data to be sent 
    /// @param cipherTextOut Returns the encrypted cipher data
    /// @return Int - how many bytes the cipherData is
    int EncryptData(const unsigned char* data, unsigned char* cipherDataOut);


    /// @brief Decrypts the data recieved over the network
    /// @param cipherData The encrypted data recieved
    /// @param dataOut Retruns the decrypted data
    /// @return Int - number of bytes of data after decryption 
    int DecryptData(const unsigned char* cipherData, unsigned char* dataOut);


    /// @brief Creates the public-private key pair for the Diffie Hellman key exchange
    /// @return Bool - success
    bool CreateDHKeys(void);


    /// @brief Will derive the AES secret key from both DH keys
    /// @return success
    bool DeriveSecretKey(void);


    // Generate all relevant contexts and keys
    Encryption();
    // Free all openssl resources
    ~Encryption();
};

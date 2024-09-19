#include <openssl/evp.h>

#include <memory>

// Memory size constants
#define AESKEY_SIZE_BYTES 32
#define AESIV_SIZE_BYTES 16
#define DH_DERIVED_SIZE_BYTES 256
#define SHA256_BYTES 32
#define SHA256_AES_ENCRYPTED_BYTES 48

class Encryption
{
private:
    // For packet encryption the first 3 bytes are not encrypted.
    // 01 02 03
    // 01 - Control byte (type of packet)
    // 02 03 - Size of encrypted packet
    // These bytes are needed for the application to determine how to deal with and read the packet
    //
    //    |--|------------|------|---------------------------------|
    // Ctrl+Size   EncryptedChecksum(sha256(IV||AES))      IV            AES ENC Payload
    //
    //  3 bytes for control and packet length
    //  E(HASH(IV||EPACKET)) - 48 bytes
    //              
    // Determined AES KEY from DH agreed key
    // The dh shared key will be 256 bytes but a hash like sha256 can be used to get our 256 bits (16 bytes) key.
    // CANNOT BE sent over network
    unsigned char key[AESKEY_SIZE_BYTES];
    
    // Initalization vector, can be sent over the network.
    // Should have MAC code to determine integrity
    unsigned char IV[AESIV_SIZE_BYTES];

    // Public peer
    EVP_PKEY* dhPeerKey = nullptr;
    // Public and private client key
    EVP_PKEY* dhKey = nullptr;

    /// @brief Creates the public-private key pair for the Diffie Hellman key exchange
    /// @return Bool - success
    bool CreateDHKeys(void);


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


    /// @brief Return the DH public key bytes 
    /// @param DHpublicKeyOut buffer to write key to (256 bytes)
    /// @return Bool - success
    bool GetDHPubKey(unsigned char* DHpublicKeyOut);

    bool SetDHPublicPeer(const unsigned char& pubKey, const size_t pubKeySize);


    /// @brief Will derive the AES secret key from both DH keys
    /// @return Bool - success
    bool DeriveSecretKey(void);



    bool CreatePacketSig(const unsigned char& packetPayload, const size_t packetPayloadLen, const unsigned char& IV, unsigned char* encSignatureOut);
    

    bool VerifyPacket(const unsigned char &packetHash, const unsigned char& IV, const unsigned char &packetPayload, const size_t packetPayloadLen);

    bool GenerateIV(unsigned char* ivOut);

    /// @brief Create a sha256 hash from input data
    /// @param data Bytes to hash
    /// @param dataSize Number of bytes to hash
    /// @param hashOut Buffer to write the hash to
    /// @return Bool - success
    bool CalculateSHA256(const unsigned char& data, const size_t dataSize, unsigned char* hashOut);


    // Generate all relevant contexts and keys
    Encryption();
    // Free all openssl resources
    ~Encryption();
};

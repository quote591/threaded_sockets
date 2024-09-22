#include <openssl/evp.h>

#include <memory>

// Memory size constants
constexpr unsigned int AESKEY_SIZE_BYTES = 32;
constexpr unsigned int AESIV_SIZE_BYTES = 16;
constexpr unsigned int DH_DERIVED_SIZE_BYTES = 256;
constexpr unsigned int DH_PUBLICKEY_SIZE_BYTES = 256;
constexpr unsigned int SHA256_BYTES = 32;
constexpr unsigned int SHA256_AES_ENCRYPTED_BYTES = 48;


class Encryption
{
private:
    // For packet encryption the first 3 bytes are not encrypted.
    // These bytes are needed for the application to determine how to deal with and read the packet
    //
    //    |--|------------|------|---------------------------------|
    // Size+Ctrl   EncryptedChecksum(sha256(IV||AES))      IV            AES ENC Payload
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
    /// @param data Data to encrypt
    /// @param plainTextLen Size of data to encrypt
    /// @param iv initalisation vector
    /// @param cipherTextOut the encrypted data returned
    /// @return Int - number of bytes of cipher text. -1 if error occured
    int EncryptData(const unsigned char& data, const size_t plainTextLen, const unsigned char& iv, std::unique_ptr<unsigned char[]>& cipherTextOut);


    /// @brief Decrypts the data recieved over the network
    /// @param cipherData encrypted data
    /// @param cipherDataLen size of encrypted data
    /// @param iv initalisation vector
    /// @param dataOut the unencrypted data returned
    /// @return Int - number of bytes after decryption. -1 if error occured
    int DecryptData(const unsigned char& cipherData, const size_t cipherDataLen, const unsigned char& iv, std::unique_ptr<unsigned char[]>& dataOut);


    /// @brief Return the DH public key bytes 
    /// @param DHpublicKeyOut buffer to write key to (256 bytes)
    /// @return Bool - success
    bool GetDHPubKey(unsigned char* DHpublicKeyOut);


    /// @brief Set DH peer public key 
    /// @param pubKey Bytes of the public key 
    /// @param pubKeySize Size of public key
    /// @return Bool - success 
    bool SetDHPublicPeer(const unsigned char& pubKey, const size_t pubKeySize);


    /// @brief Will derive the AES secret key from both DH keys
    /// @return Bool - success
    bool DeriveSecretKey(void);


    /// @brief Create signature for packet
    /// @param packetPayload IV + payload to check hash
    /// @param packetPayloadLen size of the payload to check signature
    /// @param IV Initalisation vector for encryption
    /// @param encSignatureOut Signature buffer to write to (48 bytes)
    /// @return Bool - success
    bool CreatePacketSig(const unsigned char& packetPayload, const size_t packetPayloadLen, const unsigned char& IV, unsigned char* encSignatureOut);
    

    /// @brief Verify packet using encrypted hash
    /// @param packetHash Encrypted hash
    /// @param IV Initalisation vector for decryption
    /// @param packetPayload Payload to the signature is verifying
    /// @param packetPayloadLen Size of payload
    /// @return Bool - success
    bool VerifyPacket(const unsigned char &packetHash, const unsigned char& IV, const unsigned char &packetPayload, const size_t packetPayloadLen);


    /// @brief Generate an IV (16 bytes)
    /// @param ivOut buffer to write IV to
    /// @param bytes number of bytes to generate
    /// @return Bool - success
    static bool s_GenerateIV(unsigned char* ivOut, int bytes = AESIV_SIZE_BYTES);


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

#include "encryption.hpp"
#include "../logging.hpp"

#include <openssl/dh.h>
#include <openssl/rand.h>

#include <cmath>
#include <cassert>
#include <cstring>

int Encryption::EncryptData(const unsigned char& plainText, const size_t plainTextLen, const unsigned char& iv, std::unique_ptr<unsigned char[]>& cipherTextOut)
{

    // Number of bytes the output AES will be
    int outputBytes = (std::floor(plainTextLen/16.0)+1)*16;
    // Smart pointer allocation
    std::unique_ptr<unsigned char[]> upCipherText = std::make_unique<unsigned char[]>(outputBytes);

	// First is total ct length, second is a temp variable
	int cipherTextLength, ctLen;

	EVP_CIPHER_CTX* ctx;

	try
	{
		if (!(ctx = EVP_CIPHER_CTX_new()))
			throw ("Cipher_CTX_New failed.");
		
		// Use default engine
		if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, &iv))
			throw ("EncryptInit_ex failed.");

		if (1 != EVP_EncryptUpdate(ctx, upCipherText.get(), &ctLen, &plainText, plainTextLen))
			throw ("EncryptUpdate failed.");
		cipherTextLength = ctLen;
		
		 // Write final block
		if (1 != EVP_EncryptFinal_ex(ctx, upCipherText.get()+cipherTextLength, &ctLen))
			throw ("EncryptFinal_ex failed.");

		// Add number of the final bytes to the total message length
		cipherTextLength += ctLen;

        cipherTextOut = std::move(upCipherText);
	}
	catch (const char* err)
	{
        Log::s_GetInstance()->m_LogWrite("Encryption::EncryptData", "Error: ", err);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
	}

	// Free context
	EVP_CIPHER_CTX_free(ctx);
	return cipherTextLength;
}

int Encryption::DecryptData(const unsigned char& cipherData, const size_t cipherDataLen, const unsigned char& iv, std::unique_ptr<unsigned char[]>& dataOut)
{
    // Unencrypted data will always be less than the cipher length
    std::unique_ptr<unsigned char[]> upDecryptedText = std::make_unique<unsigned char[]>(cipherDataLen);

	EVP_CIPHER_CTX* ctx;
	int plainTextLength, ciLen;

	try
	{
		if (!(ctx = EVP_CIPHER_CTX_new()))
			throw ("Cipher_CTX_New failed.");
		
		// ex - extended. Use default engine
		if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, &iv))
			throw ("DecryptInit_ex failed.");

		if (1 != EVP_DecryptUpdate(ctx, upDecryptedText.get(), &ciLen, &cipherData, cipherDataLen))
			throw ("DecryptUpdate failed.");
		plainTextLength = ciLen;
		
		 // Write final black
		if (1 != EVP_DecryptFinal_ex(ctx, upDecryptedText.get()+plainTextLength, &ciLen))
			throw ("DecryptFinal_ex failed.");

		// Add number of the final bytes to the total message length
		plainTextLength += ciLen;
	}
	catch (const char* err)
	{
        Log::s_GetInstance()->m_LogWrite("Encryption::DecryptData", "Error: ", err);
        EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
    dataOut = std::move(upDecryptedText);
	// Free context
	EVP_CIPHER_CTX_free(ctx);
	return plainTextLength;
}

bool Encryption::CreateDHKeys(void)
{
    EVP_PKEY* params = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;

    try
    {
        // Setup parameters and contexts
        if (nullptr == (params = EVP_PKEY_new()))
            throw ("Error creating PKEY.");
        
        if (1 != EVP_PKEY_assign(params, EVP_PKEY_DH, DH_get_2048_256()))
            throw ("Error assigning DH to PKEY.");

        if (!(ctx = EVP_PKEY_CTX_new(params, nullptr)))
            throw ("Error creating PKEY context.");

        // Generate a new key
        if (1 != EVP_PKEY_keygen_init(ctx))
            throw ("Error keygen init.");
        
        if (1 != EVP_PKEY_keygen(ctx, &this->dhKey))
            throw ("Error keygen.");
    }
    catch(const char* err)
    {
        Log::s_GetInstance()->m_LogWrite("Encryption::CreateDHKeys", "Error: ", err);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(params);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(params);
    return true;
}

bool Encryption::SetDHPublicPeer(const unsigned char &pubKey, const size_t pubKeySize)
{
	DH* dh = nullptr;
	BIGNUM* pubKeyBigNum = nullptr;

	try
	{
		// Create DH 
		dh = DH_get_2048_256();
		if (!dh)
			throw("Create DH failed.");

		// Convert public key to bignum
		pubKeyBigNum = BN_bin2bn(&pubKey, pubKeySize, pubKeyBigNum);
		if (!pubKeyBigNum)
			throw("Converting public key to bignum failed.");

		// Set public key to DH struct
		if (!DH_set0_key(dh, pubKeyBigNum, nullptr))
			throw("Set public key in DH struct failed.");

		this->dhPeerKey = EVP_PKEY_new();
		if (!this->dhPeerKey)
			throw("Creating PKEY struct failed.");

		if (!EVP_PKEY_assign_DH(this->dhPeerKey, dh))
			throw("Assigning DH to keystruct failed.");
	}
	catch(const char* err)
	{
        Log::s_GetInstance()->m_LogWrite("Encryption::CreateDHPKEY", "Error: ", err);
		// If err, free the PKEY struct
		EVP_PKEY_free(this->dhPeerKey);
        return false;
	}

    return true;
}

bool Encryption::GetDHPubKey(unsigned char *DHpublicKeyOut)
{
    const BIGNUM *pubKey = nullptr;
    try
    {
        // Extrac the raw bytes of the public key
        DH* dh = EVP_PKEY_get1_DH(this->dhKey);
        if (!dh)
            throw ("Error extracting dh from PKEY.");
        
        // Get private key from the struct
        // 0 - we do not own the returned keys, the DH* from dhKey does
        DH_get0_key(dh, &pubKey, nullptr);
        if (DH_DERIVED_SIZE_BYTES != BN_bn2bin(pubKey, DHpublicKeyOut))
            throw("DH public key was not 256 bytes.");
    }
    catch(const char* err)
    {
        Log::s_GetInstance()->m_LogWrite("Encryption::GetDHPubKey", "Error: ", err);
        return false;
    }
    return true;
}

bool Encryption::DeriveSecretKey(void)
{
    EVP_PKEY_CTX* ctx;

    unsigned char skey[DH_DERIVED_SIZE_BYTES];
    size_t skeyLen;

    try
    {
        ctx = EVP_PKEY_CTX_new(this->dhKey, nullptr);
        if (!ctx)
            throw ("Failed to create new PKEY context.");

        if (1 != EVP_PKEY_derive_init(ctx))
            throw ("Derive init failed.");

        // Use both DH keys to get 256 byte shared key
        if (1 != EVP_PKEY_derive_set_peer(ctx, this->dhPeerKey))
            throw ("Derive set peer failed.");
        
        if (1 != EVP_PKEY_derive(ctx, nullptr, &skeyLen))
            throw ("Failed to get derived key length.");
        if (skeyLen != DH_DERIVED_SIZE_BYTES)
            throw ("Derived key length is not 256 bytes.");
        
        if (1 != EVP_PKEY_derive(ctx, skey, &skeyLen))
            throw ("Derived key generate failed.");
    }
    catch(const char* err)
    {
        Log::s_GetInstance()->m_LogWrite("Encryption::DeriveSecretKey", "Error: ", err);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    
    // Use sha256 to turn the key into a 32 byte key for AES
    return this->CalculateSHA256(*skey, DH_DERIVED_SIZE_BYTES, this->key);
}

bool Encryption::CreatePacketSig(const unsigned char& packetPayload, const size_t packetPayloadLen, const unsigned char& IV, unsigned char* encSignatureOut)
{
    // 48 bytes for signature

    std::unique_ptr<unsigned char[]> encryptedHash;
    try
    {
        unsigned char calculatedHash[SHA256_BYTES];
        if (!this->CalculateSHA256(packetPayload, packetPayloadLen, calculatedHash))
            throw ("CalculateSHA256 failed.");
        
        if (-1 == this->EncryptData(*calculatedHash, SHA256_BYTES, IV, encryptedHash))
            throw ("EncryptedData failed.");
    }
    catch(const char* err)
    {
        Log::s_GetInstance()->m_LogWrite("Encryption::CreatePacketSig", "Error: ", err);
        return false;
    }
    std::memcpy(encSignatureOut, encryptedHash.get(), SHA256_AES_ENCRYPTED_BYTES);
    return true;
}

bool Encryption::VerifyPacket(const unsigned char &packetHash, const unsigned char& IV, const unsigned char &packetPayload, const size_t packetPayloadLen)
{
    // packetHash - 48 bytes (encrypted)
    // 32 byte hash encrypted with AES256 -> 48 bytes
    std::unique_ptr<unsigned char[]> decryptedHash; 
    try
    {
        int hashSize = this->DecryptData(packetHash, SHA256_AES_ENCRYPTED_BYTES, IV, decryptedHash);

        // Check its a sha256
        assert(hashSize == SHA256_BYTES);

        unsigned char calculatedHash[SHA256_BYTES];
        // Take our own hash
        if (!this->CalculateSHA256(packetPayload, packetPayloadLen, calculatedHash))
            throw ("CalculateSHA256 failed.");
        
        if (std::memcmp(decryptedHash.get(), calculatedHash, SHA256_BYTES))
            throw ("Invalid packet signature.");
    }
    catch(const char* err)
    {
        Log::s_GetInstance()->m_LogWrite("Encryption::VerifyPacket", "Error: ", err);
        return false;
    }

    // Verified hash
    return true;
}

bool Encryption::GenerateIV(unsigned char *ivOut, int bytes)
{
    try
    {
        if (1 != RAND_bytes(ivOut, bytes))
            throw ("RAND_pseudo_bytes failed.");
    }
    catch(const char* err)
    {
        Log::s_GetInstance()->m_LogWrite("Encryption::GenerateIV", "Error: ", err);
        return false;
    }
    return true;
}

bool Encryption::CalculateSHA256(const unsigned char& data, const size_t dataSize, unsigned char* hashOut)
{
    EVP_MD_CTX* ctx;
    try
    {
        ctx = EVP_MD_CTX_new();
        if (!ctx)
            throw ("Failed allocation from EVP_MD_CTX_new().");
        if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr))
            throw ("EVP_DigestInit_ex failed.");
        if (1 != EVP_DigestUpdate(ctx, &data, dataSize))
            throw ("EVP_DigestUpdate failed.");
        if (1 != EVP_DigestFinal_ex(ctx, hashOut, nullptr))
            throw ("EVP_DigestFinal_ex failed.");
    }
    catch(const char* err)
    {
        Log::s_GetInstance()->m_LogWrite("Encryption::CalculateSHA256", "Error: ", err);

        // Dealocate all resources
        EVP_MD_CTX_free(ctx);
        return false;
    }
    EVP_MD_CTX_free(ctx);
    return true;
}

Encryption::Encryption()
{
    this->CreateDHKeys();
}

Encryption::~Encryption()
{
    EVP_PKEY_free(dhKey);
}

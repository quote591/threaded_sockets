#include "encryption.hpp"

#include <openssl/dh.h>

#include <cmath>

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

        EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

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
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(params);
        return false;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(params);
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
        if (256 != BN_bn2bin(pubKey, DHpublicKeyOut))
            throw("DH public key was not 256 bytes.");
    }
    catch(const char* err)
    {

        return false;
    }
    return true;
}

bool Encryption::DeriveSecretKey(void)
{


    // Use both DH keys to get 256 byte shared key
    
    // Use sha256 to turn the key into a 32 byte key for AES
    return false;
}

bool Encryption::CalculateSHA256(const unsigned char* data, const size_t dataSize, unsigned char* hashOut)
{
    EVP_MD_CTX* ctx;
    try
    {
        ctx = EVP_MD_CTX_new();
        if (!ctx)
            throw ("Failed allocation from EVP_MD_CTX_new().");
        if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr))
            throw ("EVP_DigestInit_ex failed.");
        if (1 != EVP_DigestUpdate(ctx, data, dataSize))
            throw ("EVP_DigestUpdate failed.");
        if (1 != EVP_DigestFinal_ex(ctx, hashOut, nullptr))
            throw ("EVP_DigestFinal_ex failed.");
    }
    catch(const char* err)
    {
        // TODO

        // Dealocate all resources
        EVP_MD_CTX_free(ctx);
        return false;
    }
    EVP_MD_CTX_free(ctx);
    return true;
}

Encryption::~Encryption()
{
    EVP_PKEY_free(dhKey);
}
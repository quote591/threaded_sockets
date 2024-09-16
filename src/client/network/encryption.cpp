#include "encryption.hpp"

int Encryption::EncryptData(const unsigned char *plainText, unsigned char *cipherTextOut)
{
    return 0;
}

int Encryption::DecryptData(const unsigned char *cipherData, unsigned char *dataOut)
{
    return 0;
}

bool Encryption::CreateDHKeys(void)
{
    return false;
}

bool Encryption::DeriveSecretKey(void)
{

    // Use both DH keys to get 256 byte shared key
    
    // Use sha256 to turn the key into a 32 byte key for AES

    return false;
}

#include "lib.hxx"
#include "c05.hxx"


void repeating_key_xor(const std::string inputStr, const std::string key, std::string &outputHexStr)
{
/** @brief  Encrypt input string using sequential and cyclic key xor of plaintext: it is Vigenere encryption.
 *  @param  inputStr    Plaintext to be encrypted.
 *  @param  key         Encryption key.
 *  @param  outputStr      Ciphertext which encrypts input plaintext
 */


    uint8_t* keyBytes;
    uint8_t* inputBytes;
    int lenKeyBytes;
    int lenInputBytes;

    string_to_bytes(inputStr, lenInputBytes, inputBytes);
    string_to_bytes(key, lenKeyBytes, keyBytes);

    int lenOutputBytes = lenInputBytes;
    uint8_t *outputBytes = new uint8_t[lenOutputBytes];

    for (int i = 0; i < lenOutputBytes; i++)
    {
        outputBytes[i] = inputBytes[i]^keyBytes[i%lenKeyBytes];
    }

    hex_array_to_hex_string(outputBytes, lenOutputBytes, outputHexStr);
}
#include "c01.hxx"
#include "c07.hxx"
#include "c08.hxx"
#include "c10.hxx"
#include "c11.hxx"
#include <ctime>
#include <algorithm>


void generate_aes_key(const int blockLen, uint8_t*& aesKey)
{
/** @brief  Generate a random key AES
 *  @param  blockLen    The number of bytes on block, can be 16, 24 bytes
 *  @param  aesKey      Array which contains the random key
 */

    /* Init rand, with seed time(NULL) */
    srand((unsigned)time(NULL));

    aesKey = new uint8_t[blockLen];

    /* fill array by random bytes */
    for (int i = 0; i < blockLen; i++)
        aesKey[i] = (uint8_t)rand();    
}

void random_padding_before_and_after(const uint8_t* input, const int lenInput, int& lenPaddedInput, uint8_t*& paddedInput)
{
/** @brief  A padding of 5-10 bytes before and after input array
 *  @param  input           The array which should be padded
 *  @param  lenInput        The length of input array
 *  @param  lenPaddedInput  The length of padded input array
 *  @param  paddedInput     The array which contains input padded to both side.
 */
    /* Init rand, with seed time(NULL) */
    srand((unsigned)time(NULL));

    /* Choose an integer between 5-10 */
    int lenPadBefore = 5 + (rand() % 6);
    int lenPadAfter = 5 + (rand() % 6);

    uint8_t* padBefore = new uint8_t[lenPadBefore];
    uint8_t* padAfter = new uint8_t[lenPadAfter];

    /* fill array by random bytes */
    for (int i = 0; i < lenPadBefore; i++)
        padBefore[i] = (uint8_t) rand();

    /* fill array by random bytes */
    for (int i = 0; i < lenPadAfter; i++)
        padAfter[i] = (uint8_t) rand();
    
    lenPaddedInput = lenPadBefore + lenInput + lenPadAfter;
    paddedInput = new uint8_t[lenPaddedInput];

    std::string paddedInputStr;
    /* copy padBefore at the start or paddedInput */
    std::copy(padBefore, padBefore + lenPadBefore, paddedInput);

    /* copy input at the middle of paddedInput */
    std::copy(input, input + lenInput, paddedInput + lenPadBefore);

    /* copy padAfter at the end of paddedInput */
    std::copy(padAfter, padAfter + lenPadAfter, paddedInput + lenPadBefore + lenInput);
}

void encryption_oracle(const uint8_t* plaintextArray, const int lenPlaintextArray, int& lenCiphertextArray, uint8_t*& ciphertextArray)
{
/** @brief  A Oracle which take a plaintext, padded it and encrypts it by AES in ECB mode with probability 1/2 and AES in CBC mode with proba 1/2
 *  @param  plaintextArray          The input plaintext array which should be encrypted
 *  @param  lenPlaintextArray       The length of plaintext array
 *  @param  lenCiphertextArray      The length of ciphertext array encrypted by oracle
 *  @param  ciphertextArray         The ciphertext encrypted either by AES in EBC or AES in CBC mode and with unknow key.
 */
    srand((unsigned)time(NULL));

    int blockLen = 16;
    uint8_t* aesKey;
    generate_aes_key(blockLen, aesKey);

    int lenRandomPaddedPlaintext;
    uint8_t* randomPaddedPlaintext;
    random_padding_before_and_after(plaintextArray, lenPlaintextArray, lenRandomPaddedPlaintext, randomPaddedPlaintext);

    if (rand()%2)
    {
        std::cout << "Encrypted by AES ECB" << std::endl;
        encrypt_aes_128_in_ecb(randomPaddedPlaintext, lenRandomPaddedPlaintext, 1, aesKey, lenCiphertextArray, ciphertextArray);
    }
    else
    {
        std::cout << "Encrypted by AES CBC" << std::endl;
        uint8_t* IV;
        generate_aes_key(blockLen, IV);
        encrypt_aes_in_cbc(blockLen, randomPaddedPlaintext, lenRandomPaddedPlaintext, 0, aesKey, IV, lenCiphertextArray, ciphertextArray);
    }
}

void detect_block_cipher_mode(const uint8_t* ciphertextArray, const int lenCiphertextArray, std::string& detectedMode)
{
/** @brief  Algorithm which finds what block cipher mode was used by oracle to encrypt the plaintext
 *  @param  ciphertextArray     The array which contains the ciphertext encrypted by oracle
 *  @param  lenCiphertextArray  The length of the ciphertext array
 *  @param  detectedMode        The string which contains the answer of block mode used by oracle.
 */
    std::string ciphertextHexStr;
    hex_array_to_hex_string(ciphertextArray, lenCiphertextArray, ciphertextHexStr);
    
    int nbrOfBlock = ciphertextHexStr.length()/32;
    int nbrOfDiffBlock;

    nbr_of_different_block(ciphertextHexStr, nbrOfDiffBlock);
    if (nbrOfDiffBlock < nbrOfBlock)
        detectedMode = "ECB";
    else
        detectedMode = "CBC";
        
}
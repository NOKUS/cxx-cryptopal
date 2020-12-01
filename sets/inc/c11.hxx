#ifndef __C11_HXX__
#define __C11_HXX__

#include "lib.hxx"

/** @brief  Generate a random key AES
 *  @param  blockLen    The number of bytes on block, can be 16, 24 bytes
 *  @param  aesKey      Array which contains the random key
 */
void generate_aes_key(const int blockLen, uint8_t*& aesKey);

/** @brief  A padding of 5-10 bytes before and after input array
 *  @param  input           The array which should be padded
 *  @param  lenInput        The length of input array
 *  @param  lenPaddedInput  The length of padded input array
 *  @param  paddedInput     The array which contains input padded to both side.
 */
void random_padding_before_and_after(const uint8_t* input, const int lenInput, int& lenPaddedInput, uint8_t*& paddedInput);

/** @brief  A Oracle which take a plaintext, padded it and encrypts it by AES in ECB mode with probability 1/2 and AES in CBC mode with proba 1/2
 *  @param  plaintextArray          The input plaintext array which should be encrypted
 *  @param  lenPlaintextArray       The length of plaintext array
 *  @param  lenCiphertextArray      The length of ciphertext array encrypted by oracle
 *  @param  ciphertextArray         The ciphertext encrypted either by AES in EBC or AES in CBC mode and with unknow key.
 */
void encryption_oracle(const uint8_t* plaintextArray, const int lenPlaintextArray, int& lenCiphertextArray, uint8_t*& ciphertextArray);

/** @brief  Algorithm which finds what block cipher mode was used by oracle to encrypt the plaintext
 *  @param  ciphertextArray     The array which contains the ciphertext encrypted by oracle
 *  @param  lenCiphertextArray  The length of the ciphertext array
 *  @param  detectedMode        The string which contains the answer of block mode used by oracle.
 */
void detect_block_cipher_mode(const uint8_t* ciphertextArray, const int lenCiphertextArray, std::string& detectedMode);

#endif /*__C11_HXX__*/
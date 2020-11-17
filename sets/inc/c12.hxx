#ifndef __C12_HXX__
#define __C12_HXX__

#include "lib.hxx"

/** @brief  A oracle which take a plaintext, pads a unknow text and encypts all of them with AES in ECB mode, with an unknow key. 
 *  @param  plaintextArray      Text which should be encrypted by oracle
 *  @param  lenPlaintextArray   length of array which containt plaintext
 *  @param  lenCiphertextArray  length of array which containt ciphertext produice by oracle
 *  @param  ciphertextArray     Text which is output of encryption on plaintextArray by the oracle
 */
void encryption_ecb_oracle(const uint8_t* plaintextArray, const int lenPlaintextArray, int& lenCiphertextArray, uint8_t*& ciphertextArray);

/** @brief  Find the block size of AES used by oracle
 *  @param  blockLen    The length of block AES used by oracle
 */
void block_size_cipher(int& blockLen);

/** @brief Check if oracle is using AES in ECB mode or No
 *  @param  isEcbMode   the answer algorithm
 */
void detect_aes_mode(bool& isEcbMode);

/** @brief  Algorithm which decrypt the unknow text used by oracle when it encrypts some plaintext
 *  @param  lenPlaintextArray   The length of the array which contains unknow text used by oracle
 *  @param  plaintextArray      array which contains unknow text used by oracle.
 */
void ecb_decryption(int& lenPlaintextArray, uint8_t*& plaintextArray);

#endif /*__C12_HXX__*/
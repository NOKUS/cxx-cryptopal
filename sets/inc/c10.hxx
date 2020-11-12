#ifndef __C10_HXX__
#define __C10_HXX__

#include "lib.hxx"
#include "c01.hxx"

/** @brief  Algorithm which copies a subset of array to anther array.
 *  @param  inputArray      Array that we want to copy a subarray
 *  @param  beginInput      Index of inputArray where copy should begin
 *  @param  endInput        Index of input array where copy should end
 *  @param  beginOutput     Index of output array where paste should begin
 *  @param  outputArray     Array which should contain the copy of subarray. 
 */
void copy_array(const uint8_t* inputArray, const int beginInput, const int endInput, const int beginOutput, uint8_t*& outputArray);

/** @brief  Algorithm which copies an array to another one.
 *  @param  inputArray  Array that we want to copy
 *  @param  lenInputArray   Length of the input array
 *  @param  lenOutputArray  Length of the output array
 *  @param  outputArray     Array which should contain the first one
 */
void copy_array(const uint8_t* inputArray, const int lenInputArray, const int& lenOutputArray, uint8_t*& outputArray);

/** @brief  Algorithm which computes the AES encryption of an array plaintext in CBC mode
 *  @param  lenBlock                The length of the blocks
 *  @param  plaintextArray          The byte array which contains plaintext
 *  @param  lenPlaintextArray       The length of the input plaintext byte array
 *  @param  pad                     The bit which define if algorithm should use autopadding or not
 *  @param  key                     The array which contains secret key
 *  @param  IV                      The initialization vector 
 *  @param  lenCiphertextArray      The length of the output ciphertext array
 *  @param  ciphertextArray         The array which contains ciphertext
 */
void encrypt_aes_in_cbc(const int lenBlock, const uint8_t* plaintextArray, const int lenPlaintextArray, const bool pad, const uint8_t* key, const uint8_t* IV, int& lenCiphertextArray, uint8_t*& ciphertextArray);

/** @brief  Algorithm which computes the AES-128 decryption of an array ciphertext in the CBC mode
 *  @param  lenBlock                The length of the blocks
 *  @param  ciphertextArray         The array which contains ciphertext
 *  @param  lenCiphertextArray      The length of the input ciphertext byte array
 *  @param  pad                     The bit which define if algorithm should use autopadding or not
 *  @param  key                     The array which contains secret key
 *  @param  IV                      The initialization vector 
 *  @param  lenPlaintextArray       The length of the output plaintext array
 *  @param  plaintextArray          The array which contains plaintext
 */
void decrypt_aes_in_cbc(const int lenBlock, const uint8_t* ciphertextArray, const int lenCiphertextArray, const bool pad, const uint8_t* key, uint8_t* IV, int& lenPlaintextArray, uint8_t*& plaintextArray);

/** @brief  Algorithme which computes AES decryption in CBC mode for a text contains in a file
 *  @param  inputFileName   The string which contains fullname where to find file
 *  @param  keyStr          The string which contains secret key use to decrypt text
 *  @param  IVStr           The initialization vector
 *  @param  outputFileName  The string which contains fullname where file will be saved
 */
void decrypt_cbc_text(const std::string inputFileName, const std::string keyStr, const std::string IVStr, std::string& outputFileName);

#endif /*__C10_HXX__*/
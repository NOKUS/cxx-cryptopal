#ifndef __C07_HXX__
#define __C07_HXX__

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "lib.hxx"

/** @brief  Algorithm which computes the AES-128 encryption of an array plaintext in the mode ECB
 *  @param  ptxtArray       The byte array which contains plaintext
 *  @param  lenPtxtArray    The length of the input plaintext byte array
 *  @param  aesKey          The array which contains secret key
 *  @param  lenCtxtArray    The length of the output ciphertext array
 *  @param  ctxtArray       The array which contains ciphertext
 */
void encrypt_aes_128_in_ecb(const uint8_t* ptxtArray, const int lenPtxtArray, const uint8_t* aesKey, int& lenCtxtArray, uint8_t* &ctxtArray);

/** @brief  Algorithm which computes the AES-128 decryption of an array ciphertext in the mode ECB
 *  @param  ctxtArray       The array which contains ciphertext
 *  @param  lenCtxtArray    The length of the input ciphertext byte array
 *  @param  aesKey          The array which contains secret key
 *  @param  lenPtxtArray    The length of the output plaintext array
 *  @param  ptxtArray       The array which contains plaintext
 */
void decrypt_aes_128_in_ecb(const uint8_t* ctxtArray, const int lenCtxtArray, const uint8_t* aesKey, int& lenPtxtArray, uint8_t* &ptxtArray);

/** @brief  Algorithme which computes AES-128 decryption in ECB mode for a text contains in a file
 *  @param  inputFileName   The string which contains fullname where to find file
 *  @param  aesKeyStr       The string which contains secret key use to decrypt text
 *  @param  outputFileName  The string which contains fullname where file will be saved
 */
void decryption_aes_128_in_ecb_mode(const std::string inputFileName, const std::string aesKeyStr, std::string& outputFileName);

#endif /*__C07_HXX__*/
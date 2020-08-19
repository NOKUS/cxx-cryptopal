#ifndef __C05_HXX__
#define __C05_HXX__

#include "lib.hxx"
#include "c01.hxx"

/** @brief  Encrypt input string using sequential and cyclic key xor of plaintext: it is Vigenere encryption.
 *  @param  inputStr    Plaintext to be encrypted.
 *  @param  key         Encryption key.
 *  @param  output      Ciphertext which encrypts input plaintext
 */
void repeating_key_xor(const std::string inputStr, const std::string key, std::string &outputHexStr);

#endif /*__C05_HXX__*/
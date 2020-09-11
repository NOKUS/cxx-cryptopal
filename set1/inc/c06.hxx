#ifndef __C06_HXX__
#define __C06_HXX__

#include "lib.hxx"
#include "c01.hxx"

/** @brief  Compute the Hamming weight of an integer represented as bytes array
 *  @param  input       bytes array of a integer that we want to compute hamming weight
 *  @param  lenInput    length of the input bytes array
 *  @param  output      the hamming weight of input.
 */
void hamming_weight(const uint8_t* input, const int lenInput, int& output);

/** @brief  Compute Hamming distance between two integers represented as bytes array of same length
 *  @param  input0      bytes array which represents the first integer
 *  @param  lenInput0   length of firt input bytes array
 *  @param  input1      bytes arrays which represents the second integer
 *  @param  lenInput1   length of secont input bytes array
 *  @param  output      the hamming distance between input0 and input1
 */
void hamming_distance(const uint8_t* input0, const int lenInput0, const uint8_t* input1, const int lenInput1, int& output);

/** @brief  Find the key size for a ciphertext encrypted with Vigenere encryption.
 *  @param  input       A bytes array which represents a ciphertext.
 *  @param  lenInput    Length of input array.
 *  @param  KEYSIZE     The size of key which encrypts the input ciphertext.
 */
void find_key_size(const uint8_t* input, const int lenInput, int& KEYSIZE);

/** @brief  Partition the input text into a set of KEYSIZE text where arrayOfOutput[i] is the text composed of all character at position i%KEYSIZE in the input text
 *  @param  input           bytes array which correspond to text to partition into a set of KEYSIZE text
 *  @param  lenInput        the length of input bytes array text
 *  @param  KEYSIZE         the length of key which encrypts input text with Vigenere Algorithm
 *  @param  commonLenOutput common length of each bytes array in the set of text
 *  @param  arrayOfOutput   set (array of pointer to bytes array) of (bytes array) text partitioned from input (bytes array) text
 */
void partition_text(const uint8_t* input, const int lenInput, const int KEYSIZE, int &communLenOutput, uint8_t** &arrayOfOutput);

/** @brief  From partitionned Vigenere ciphertext and KEYSIZE, extract de secret key
 *  @param  arrayInput      a set (array of pointer to bytes array) of text partitioned
 *  @param  communLenInput  a commun length of each array in the set of input array
 *  @param  KEYSIZE         the size of Vigenere key which encrypts set of input array
 *  @param  KEY             the key of Vigenere which encrypts set of input array
 */
void find_key(uint8_t** setInputArray, const int communLenInput, const int KEYSIZE, uint8_t* &KEY);

/** @brief  Decrypt ciphertext array encrypted with the Vigenere algorithm
 *  @param  ctxtArray           Ciphertext array which is encrypted by Vigenere algorithm
 *  @param  lenCtxtArray        Length of input ciphertext array
 *  @param  KEYSIZE             Size of the key which encrypts the ciphertext array.
 *  @param  encryptedKeyArray   Array which contains encryption key
 *  @param  lenPtxtArray        Length of array which contains decrypted text
 *  @param  ptxtArray           Array which contains decrypted text.
 */
void decrypt_vigenere(const uint8_t* ctxtArray, const int lenCtxtArray, const int KEYSIZE, const uint8_t* encryptedKeyArray, int &lenPtxtArray, uint8_t* &ptxtArray);

/** @brief  Take a file name which contains text encrypted by a Vigenere algorithm and return a file which contains decrypted text and decryption key.
 *  @param  inputFileName   File which contains encrypted text
 *  @param  KEY             Key which is used to encrypt text in the input file
 *  @param  outputFileName  File which contains decrypted text
 */
void break_repeating_key_xor(const std::string inputFileName, std::string &KEY, std::string &outputFileName);

#endif /*__C06_HXX__*/
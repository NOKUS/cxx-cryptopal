#ifndef __C08_HXX__
#define __C08_HXX__

#include "lib.hxx"

/** @brief  Compute the number of different 16 bytes blocks in the input ciphertext string
 *  @param  ctxtHexStr      A hex string which represents a ciphertext from one cryptographic algorithm
 *  @param  nbrOfBlocks     The number of different 16 bytes blocks in ctxtHexStr
 */
void nbr_of_different_block(const std::string ctxtHexStr, int& nbrOfBlocks);

/** @brief  Take a file which contains ciphertexts represented as hex string and find the one which is encrypted with AES-128 in ECB mode
 *  @param  inputFileName   Name of file which contains ciphertext
 *  @param  goodAesEcbCtxt  Is the only ciphertext which is encrypted by AES-128 in ECB mode in the input file.
 *  @param  nbrOfBlockRepetition    Is the number of blocks which is repeted at least once
 */
void detect_aes_in_ecb_mode(std::string inputFileName, std::string& goodAesEcbCtxt, int& nbrOfBlockRepetition);

#endif /*__C08_HXX__*/
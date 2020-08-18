#ifndef __C04_HXX__
#define __C04_HXX__

#include "lib.hxx"
#include "c03.hxx"

/** @brief  Takes a file which containts hex encoded strings and find single one which is encrypted by single-character XOR. 
 *  @param  inputFileName   Name of file which contains hex encode strings.
 *  @param  outputCtxtStr   Text in the input file which is encrypted with single-character XOR.
 *  @param  bestScore       The score of string which gets the best norm L1 value for every encrypted text in input file. 
 *  @param  key             Key which encrypt the text which is encrypted by single-character XOR.
 *  @param  outputPtxtStr   Decrypted text which was encrypted by single-characte XOR ans key.
 */
void detect_single_character_xor(const std::string inputFileName, std::string &outputCtxtStr, float &bestScore, uint8_t &key, std::string &outputPtxtStr);
#endif /*__C04_HXX__*/